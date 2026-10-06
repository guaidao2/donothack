// Package ac 实现 Aho-Corasick 多模式匹配。
//
// 两个用途：
//  1. 算子里做关键词批量匹配（pm / pmFromFile）。
//  2. 规则集的**预筛**：把所有规则的字面量汇进一个自动机，一次扫描得到
//     "可能命中的规则集合"，只对候选跑昂贵算子。这是低配下性能的主要来源
//     （docs/PERFORMANCE.md §4）。
//
// 设计取舍：
//   - 边用有序小切片 + 线性查找，而不是 256 长度的数组或 map。
//     每个节点的出边通常只有 1~5 条，线性查找比哈希快，内存也省得多
//     （两个数量级的差距：1 万条字面量时是几 MB 对几百 MB）。
//   - 输出用"字典后缀链"（dictLink）而不是把所有后缀输出复制到每个节点，
//     否则内存会随模式集爆炸。
//   - 扫描结果通过回调返回，避免每次扫描都分配结果切片。
package ac

// Pattern 是注册进自动机的一个模式。
type Pattern struct {
	// Literal 是要匹配的字面量（调用方负责保证非空）。
	Literal []byte
	// ID 由调用方定义，扫描时原样回传（例如规则索引）。
	ID int32
}

type edge struct {
	ch   byte
	next int32
}

type node struct {
	next     []edge // 按 ch 升序
	fail     int32
	dictLink int32   // 最近的、有输出的 fail 祖先（-1 表示没有）
	out      []int32 // 在这里结束的模式 ID
}

// Matcher 是编译好的自动机。**构建后只读，可并发使用。**
type Matcher struct {
	nodes    []node
	patterns int
	maxLen   int
}

// New 构建自动机。
func New(patterns []Pattern) *Matcher {
	m := &Matcher{nodes: make([]node, 1, 64)}
	m.nodes[0].fail = 0
	m.nodes[0].dictLink = -1

	for _, p := range patterns {
		if len(p.Literal) == 0 {
			continue
		}
		cur := int32(0)
		for _, c := range p.Literal {
			cur = m.addEdge(cur, c)
		}
		m.nodes[cur].out = append(m.nodes[cur].out, p.ID)
		if len(p.Literal) > m.maxLen {
			m.maxLen = len(p.Literal)
		}
		m.patterns++
	}
	m.buildFailLinks()
	return m
}

func (m *Matcher) addEdge(from int32, c byte) int32 {
	n := &m.nodes[from]
	// 线性查找（出边少）
	for i := range n.next {
		if n.next[i].ch == c {
			return n.next[i].next
		}
		if n.next[i].ch > c {
			// 插入保持有序
			id := int32(len(m.nodes))
			m.nodes = append(m.nodes, node{fail: 0, dictLink: -1})
			n.next = append(n.next, edge{})
			copy(n.next[i+1:], n.next[i:])
			n.next[i] = edge{ch: c, next: id}
			return id
		}
	}
	id := int32(len(m.nodes))
	m.nodes = append(m.nodes, node{fail: 0, dictLink: -1})
	n.next = append(n.next, edge{ch: c, next: id})
	return id
}

func (m *Matcher) buildFailLinks() {
	queue := make([]int32, 0, len(m.nodes))
	for _, e := range m.nodes[0].next {
		m.nodes[e.next].fail = 0
		m.nodes[e.next].dictLink = -1
		queue = append(queue, e.next)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range m.nodes[cur].next {
			f := m.nodes[cur].fail
			for f != 0 && m.step(f, e.ch) < 0 {
				f = m.nodes[f].fail
			}
			if nxt := m.step(f, e.ch); nxt >= 0 && nxt != e.next {
				m.nodes[e.next].fail = nxt
			} else {
				m.nodes[e.next].fail = 0
			}
			fl := m.nodes[e.next].fail
			if len(m.nodes[fl].out) > 0 {
				m.nodes[e.next].dictLink = fl
			} else {
				m.nodes[e.next].dictLink = m.nodes[fl].dictLink
			}
			queue = append(queue, e.next)
		}
	}
}

// step 返回从 from 沿 c 转移到的节点，找不到返回 -1。
func (m *Matcher) step(from int32, c byte) int32 {
	n := m.nodes[from].next
	for i := range n {
		if n[i].ch == c {
			return n[i].next
		}
		if n[i].ch > c {
			return -1
		}
	}
	return -1
}

// nextState 返回自动机在 from 读入 c 后的状态（含 fail 回溯）。
func (m *Matcher) nextState(from int32, c byte) int32 {
	cur := from
	for {
		if nxt := m.step(cur, c); nxt >= 0 {
			return nxt
		}
		if cur == 0 {
			return 0
		}
		cur = m.nodes[cur].fail
	}
}

// Scan 扫描 hay，对每个命中调用 fn(id, endOffset)。fn 返回 false 时提前结束。
//
// endOffset 是命中的最后一个字节下标（含）。
func (m *Matcher) Scan(hay []byte, fn func(id int32, endOffset int) bool) {
	if m.patterns == 0 || len(hay) == 0 {
		return
	}
	cur := int32(0)
	for i := 0; i < len(hay); i++ {
		cur = m.nextState(cur, hay[i])
		for id := range m.nodes[cur].out {
			if !fn(m.nodes[cur].out[id], i) {
				return
			}
		}
		for dl := m.nodes[cur].dictLink; dl >= 0; {
			for id := range m.nodes[dl].out {
				if !fn(m.nodes[dl].out[id], i) {
					return
				}
			}
			dl = m.nodes[dl].dictLink
		}
	}
}

// MatchAny 报告是否有任意模式命中（比 Scan 快，适合只关心布尔结果的场景）。
func (m *Matcher) MatchAny(hay []byte) bool {
	found := false
	m.Scan(hay, func(int32, int) bool { found = true; return false })
	return found
}

// Patterns 返回注册的模式数量。
func (m *Matcher) Patterns() int { return m.patterns }

// Nodes 返回自动机节点数（用于启动日志与预算校验）。
func (m *Matcher) Nodes() int { return len(m.nodes) }

// MaxLen 返回最长模式长度（扫描时可据此提前结束的优化依据）。
func (m *Matcher) MaxLen() int { return m.maxLen }

// Package control 是控制面：**所有写操作唯一入口**。
//
// 契约（docs/DESIGN.md §13、docs/CONSOLE.md §2）：
//
//	解析 → 校验 → 内置语料自测 → 原子替换 → 失败回滚并把错误回显
//
// 三条硬约束：
//
//  1. **数据面只读**：数据面拿到的是不可变 State 快照，永远不阻塞在控制台上。
//     控制台慢、卡住、甚至被攻击，都不影响转发与检测。
//  2. **单写者**：所有变更串行执行（一把锁），不存在两个变更交错出中间态。
//  3. **改错了能退回**：Apply 失败时旧 State 原样保留；新 State 只有在
//     全部校验通过后才被 atomically 换上去。**绝不出现"改一半"的状态**。
//
// 为什么要这么严：WAF 的配置能一句话把线上打挂（一条宽泛正则、一个错的状态码）。
// 所以"预览 + 自测 + 回滚"不是体验优化，是安全要求。
package control

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"donothack/internal/blockpage"
	"donothack/internal/rules"
)

// State 是不可变的运行时状态快照。
//
// **所有字段在发布后都不得修改**（包括它们指向的对象）。要改就构造新 State。
type State struct {
	// Version 是内容哈希，进审计与响应体（"这次的改动是哪个版本"）。
	Version string
	Since   time.Time
	// Reason 记录这个版本是怎么来的（启动 / 控制台改拦截页 / 重载规则…）。
	Reason string

	RuleSet   *rules.RuleSet
	BlockPage BlockPageState
	// RateLimit 是当前限速参数（值类型，改了就换一份新的）。
	RateLimit RateLimitState
	// DisabledRules 是控制台里被停用的规则 ID 集合（重载规则时带上）。
	DisabledRules map[string]bool
}

// BlockPageState 是拦截页的当前状态。
type BlockPageState struct {
	Options    blockpage.Options
	CustomHTML string
	// File 是自定义模板落盘路径（空表示只用内存里的，不落盘）。
	File string
	// Renderer 是编译好的渲染器。
	Renderer *blockpage.Renderer
}

// RateLimitState 是限速参数的可热改部分。
type RateLimitState struct {
	Enabled      bool
	RPS          float64
	Burst        float64
	BanAfterHits int
	BanWindow    time.Duration
	BanDuration  time.Duration
	Whitelist    []string
}

// Applier 由数据面实现：控制面把新状态推给它们。
//
// 实现必须**非阻塞**且**不失败**：数据面不能因为控制台的操作而卡住。
type Applier interface {
	ApplyRuleset(rs *rules.RuleSet)
	ApplyBlockPage(renderer *blockpage.Renderer, opts blockpage.Options)
	ApplyRateLimit(st RateLimitState)
}

// Mutation 是一次变更。
//
// Apply 拿到当前状态，返回新状态与警告；返回 error 则整次变更被拒绝，
// 当前状态**一个字节都不动**。
type Mutation interface {
	// Name 是变更名称（进操作审计）。
	Name() string
	// Apply 计算新状态。实现应当是纯函数：不修改传入的 cur。
	Apply(cur *State) (next *State, warnings []string, err error)
}

// OpRecord 是一条操作审计。
type OpRecord struct {
	At       time.Time `json:"at"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	From     string    `json:"from_version"`
	To       string    `json:"to_version,omitempty"`
	OK       bool      `json:"ok"`
	Warnings []string  `json:"warnings,omitempty"`
	Error    string    `json:"error,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Remote   string    `json:"remote,omitempty"`
}

// Control 是控制面实例。
type Control struct {
	mu  sync.Mutex // 单写者
	cur atomic.Pointer[State]
	app Applier

	// 操作审计（有界环形）
	opsMu   sync.RWMutex
	ops     []OpRecord
	opsHead int
	opsSize int

	// 订阅（SSE / 长轮询用）
	subMu   sync.Mutex
	subs    map[int]chan struct{}
	nextSub int

	version atomic.Uint64 // 单调递增的版本号（配合内容哈希）
}

// Options 是控制面构造参数。
type Options struct {
	Initial *State
	Applier Applier
	// OpsCapacity 是操作审计保留条数。
	OpsCapacity int
}

// New 构造控制面。
func New(o Options) *Control {
	if o.OpsCapacity <= 0 {
		o.OpsCapacity = 256
	}
	c := &Control{
		app:  o.Applier,
		subs: map[int]chan struct{}{},
		ops:  make([]OpRecord, o.OpsCapacity),
	}
	if o.Initial != nil {
		st := *o.Initial
		if st.Since.IsZero() {
			st.Since = time.Now()
		}
		if st.Version == "" {
			st.Version = "v1"
		}
		c.cur.Store(&st)
		c.version.Store(1)
	}
	return c
}

// Snapshot 返回当前状态（只读）。
func (c *Control) Snapshot() *State { return c.cur.Load() }

// Subscribe 订阅状态变更。返回的 channel 在每次成功变更后收到一个信号（容量 1，
// 不阻塞发布者）；调用返回的 cancel 取消订阅。
func (c *Control) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	c.subMu.Lock()
	id := c.nextSub
	c.nextSub++
	c.subs[id] = ch
	c.subMu.Unlock()

	cancel := func() {
		c.subMu.Lock()
		delete(c.subs, id)
		c.subMu.Unlock()
	}
	return ch, cancel
}

func (c *Control) notify() {
	c.subMu.Lock()
	for _, ch := range c.subs {
		select {
		case ch <- struct{}{}:
		default: // 订阅者还没处理上一个信号：丢掉这次，别把发布者拖住
		}
	}
	c.subMu.Unlock()
}

// Preview 干跑一次变更：**不替换当前状态**，只把结果与警告返回。
//
// 这是"改之前先看看会发生什么"的入口，控制台里所有写操作都应当先走它。
func (c *Control) Preview(m Mutation) (*State, []string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur := c.cur.Load()
	if cur == nil {
		return nil, nil, fmt.Errorf("控制面尚未初始化")
	}
	return m.Apply(cur)
}

// Apply 执行变更：校验 → 编译 → 原子替换 → 通知订阅者。
//
// 任何一步失败都返回 error，且当前状态保持不变。
func (c *Control) Apply(m Mutation, actor, remote string) (*State, []string, error) {
	c.mu.Lock()
	cur := c.cur.Load()
	if cur == nil {
		c.mu.Unlock()
		return nil, nil, fmt.Errorf("控制面尚未初始化")
	}

	next, warnings, err := m.Apply(cur)
	if err != nil {
		c.mu.Unlock()
		c.recordOp(OpRecord{
			At: time.Now(), Actor: actor, Action: m.Name(),
			From: cur.Version, OK: false, Error: err.Error(), Remote: remote,
		})
		return nil, warnings, err
	}
	// 变更实现返回了 cur 本身（没改）→ 视为无变化，避免无意义的版本推进
	if next == nil {
		c.mu.Unlock()
		return cur, warnings, nil
	}

	st := *next
	// **每次成功变更都推进版本号**：前端与审计要靠它判断"改动是否生效"。
	// 之前的实现只在版本为空时才赋值，导致改完还是 v1，没人知道到底改没改。
	st.Version = fmt.Sprintf("v%d", c.version.Add(1))
	if st.Since.IsZero() {
		st.Since = time.Now()
	}
	c.cur.Store(&st)

	// 推给数据面。**在锁内做**：保证数据面看到的顺序与控制面一致；
	// 实现方必须非阻塞（都是原子替换，符合要求）。
	if c.app != nil {
		if st.RuleSet != nil {
			c.app.ApplyRuleset(st.RuleSet)
		}
		if st.BlockPage.Renderer != nil {
			c.app.ApplyBlockPage(st.BlockPage.Renderer, st.BlockPage.Options)
		}
		c.app.ApplyRateLimit(st.RateLimit)
	}
	c.mu.Unlock()

	c.recordOp(OpRecord{
		At: time.Now(), Actor: actor, Action: m.Name(),
		From: cur.Version, To: st.Version, OK: true, Warnings: warnings, Remote: remote,
	})
	c.notify()
	return &st, warnings, nil
}

// Ops 返回最近的操作审计（最新在前）。
func (c *Control) Ops(limit int) []OpRecord {
	if limit <= 0 {
		limit = 50
	}
	c.opsMu.RLock()
	defer c.opsMu.RUnlock()
	n := c.opsSize
	if limit > n {
		limit = n
	}
	out := make([]OpRecord, 0, limit)
	for i := 0; i < limit; i++ {
		idx := (c.opsHead - 1 - i + len(c.ops)) % len(c.ops)
		out = append(out, c.ops[idx])
	}
	return out
}

func (c *Control) recordOp(r OpRecord) {
	c.opsMu.Lock()
	defer c.opsMu.Unlock()
	c.ops[c.opsHead] = r
	c.opsHead = (c.opsHead + 1) % len(c.ops)
	if c.opsSize < len(c.ops) {
		c.opsSize++
	}
}

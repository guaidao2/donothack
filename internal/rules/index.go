package rules

import (
	"fmt"

	"donothack/internal/ac"
	"donothack/internal/operator"
	"donothack/internal/tx"
)

// phaseIndex 是一个阶段的编译产物：规则列表 + 预筛自动机 + 不可预筛的规则。
type phaseIndex struct {
	rules    []*CompiledRule
	bits     int // 位图需要多少个 uint64
	prefilte *ac.Matcher
	// always 是"没有字面量、必须每请求评估"的规则下标。
	// 这个集合越大，预筛的收益越低 —— 它占规则总数的比例是规则集质量的硬指标。
	always []int32
	// collections 是本阶段规则引用到的集合名（去重）。
	// 预筛只扫这些集合的值，不必把每个请求的全部输入都扫一遍。
	collections []string
}

// buildIndex 为每个阶段建立索引与预筛自动机。
//
// 预筛思路（docs/PERFORMANCE.md §4）：把所有规则的字面量汇进**同一个**自动机，
// 终态映射回规则下标；请求进来先用一次扫描得到候选规则集合，
// 再只对候选跑昂贵算子。
func (rs *RuleSet) buildIndex(opts Options) error {
	for p := tx.PhaseRequestHeaders; p <= tx.PhaseRequestBody; p++ {
		idx := &phaseIndex{}

		// 先收集本阶段启用的规则
		var phaseRules []*CompiledRule
		for _, r := range rs.allRules {
			// chainMember 只是链条成员，由链首统一执行，不单独进预筛与评估。
			if r.Enabled && !r.chainMember && r.Phase == p {
				phaseRules = append(phaseRules, r)
			}
		}
		if len(phaseRules) == 0 {
			continue
		}
		idx.rules = phaseRules
		idx.bits = (len(phaseRules) + 63) / 64

		var patterns []ac.Pattern
		colSeen := map[string]bool{}
		for i, r := range phaseRules {
			for _, tg := range r.Targets {
				if !colSeen[tg.Collection] {
					colSeen[tg.Collection] = true
					idx.collections = append(idx.collections, tg.Collection)
				}
			}
			if !r.Prefilterable {
				idx.always = append(idx.always, int32(i))
				rs.localities.NoLiteralRules++
				continue
			}
			rs.localities.LiteralRules++
			for _, lit := range r.Literals {
				patterns = append(patterns, ac.Pattern{Literal: lit, ID: int32(i)})
			}
		}

		if len(patterns) > 0 {
			idx.prefilte = ac.New(patterns)
			rs.localities.PrefilterNodes += idx.prefilte.Nodes()
		}
		rs.phases[int(p)] = idx
	}

	// 短字面量的统计（不进自动机但不影响规则执行）
	for _, r := range rs.allRules {
		if !r.Enabled {
			continue
		}
		if r.Prefilterable {
			continue
		}
		if len(r.Literals) > 0 {
			rs.localities.ShortLiterals++
		}
	}

	noLiteralRatio := 0.0
	if rs.localities.Enabled > 0 {
		noLiteralRatio = float64(rs.localities.NoLiteralRules) / float64(rs.localities.Enabled)
	}
	if noLiteralRatio > 0.20 {
		rs.localities.Warnings = append(rs.localities.Warnings, fmt.Sprintf(
			"无字面量规则占比 %.0f%%（%d/%d），超过 20%%：这些规则每请求都要评估，预筛收益被拉低。建议给它们补可预筛的字面量（见 docs/RULES.md §9.2 第 9 条）",
			noLiteralRatio*100, rs.localities.NoLiteralRules, rs.localities.Enabled))
	}
	if rs.localities.ShortLiterals > 0 {
		rs.localities.Warnings = append(rs.localities.Warnings, fmt.Sprintf(
			"有 %d 条规则的唯一字面量短于 %d 字节，无法进预筛（短字面量会让自动机在每个输入上命中）",
			rs.localities.ShortLiterals, opts.MinLiteralLen))
	}
	return nil
}

// Stats 返回加载期统计。
func (rs *RuleSet) Stats() Stats { return rs.localities }

// Rules 返回全部规则（只读）。
func (rs *RuleSet) Rules() []*CompiledRule { return rs.allRules }

// Rule 按 ID 查规则。
func (rs *RuleSet) Rule(id string) (*CompiledRule, bool) {
	r, ok := rs.byID[id]
	return r, ok
}

// Exceptions 返回全部例外（只读）。
func (rs *RuleSet) Exceptions() []*Exception { return rs.exceptions }

// Chains 返回去重后的变换链（只读）。
func (rs *RuleSet) Chains() []ChainInfo { return rs.chains }

// EvalScratch 是求值期的可复用缓冲，避免每请求分配。
//
// 由调用方（engine）持有并按请求复用：位图与变换缓冲都在这里，
// 稳态下不产生分配。
type EvalScratch struct {
	bits    []uint64
	vals    []byte
	variant []byte
	hits    []Hit
}

// Hit 是一次命中。
type Hit struct {
	Rule    *CompiledRule
	Target  string // 形如 ARGS:username
	ValIdx  int
	Detail  string
	Matched int

	// Before / After 是命中位置的原始值与变换后的值。
	//
	// 只存**切片引用**，不复制、不分配 —— 但要注意生命周期：
	// 它们指向请求的内存，请求结束即失效。需要留存必须当场转成字符串
	// （eventstore 就是这么做的：入口处做一次可打印化 + 截断）。
	Before []byte
	After  []byte
}

// Reset 清空但保留容量。
func (s *EvalScratch) Reset() {
	for i := range s.bits {
		s.bits[i] = 0
	}
	s.bits = s.bits[:0]
	s.hits = s.hits[:0]
	s.vals = s.vals[:0]
	s.variant = s.variant[:0]
}

// ensureBits 保证位图容量足够并清零。
func (s *EvalScratch) ensureBits(words int) []uint64 {
	if cap(s.bits) < words {
		s.bits = make([]uint64, words)
	}
	s.bits = s.bits[:words]
	for i := range s.bits {
		s.bits[i] = 0
	}
	return s.bits
}

func (s *EvalScratch) setBit(i int32) {
	w := int(i) >> 6
	if w >= len(s.bits) {
		return
	}
	s.bits[w] |= 1 << uint(i&63)
}

func (s *EvalScratch) hasBit(i int32) bool {
	w := int(i) >> 6
	if w >= len(s.bits) {
		return false
	}
	return s.bits[w]&(1<<uint(i&63)) != 0
}

// Exceptions 的匹配与规则禁用判断放在 engine 里做（需要 tx 上下文）。
var _ = operator.Names

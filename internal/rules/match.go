package rules

import (
	"donothack/internal/kv"
	"donothack/internal/operator"
	"donothack/internal/tx"
)

// Match 在指定阶段评估规则集。
//
// 执行顺序（docs/PERFORMANCE.md §4）：
//  1. 先算候选：把本阶段涉及的所有值，按**去重后的变换链**各算一次，
//     对每个变换结果做一次 Aho-Corasick 扫描，命中即点亮对应规则的位。
//     无字面量的规则直接点亮（它们每请求都要跑）。
//  2. 再评估候选：只对点亮了的规则，按其自己的 target 与变换链逐值跑算子。
//
// 这样每请求的变换次数从"规则数 × 链长"降到"不同链数 × 值数"，
// 算子执行从"全部规则"降到"候选规则"。
//
// emit 返回 false 时立即停止（用于 hard_block 短路）。
func (rs *RuleSet) Match(t *tx.Transaction, p tx.Phase, sc *EvalScratch, emit func(Hit) bool) {
	idx := rs.phases[int(p)]
	if idx == nil || len(idx.rules) == 0 {
		return
	}

	bits := sc.ensureBits(idx.bits)
	for _, i := range idx.always {
		w := int(i) >> 6
		bits[w] |= 1 << uint(i&63)
	}

	// ---- 1) 预筛 ----
	if idx.prefilte != nil && len(rs.chains) > 0 {
		for _, col := range idx.collections {
			expandCollection(&t.Vars, col, func(_ string, val []byte) bool {
				if len(val) == 0 {
					return true
				}
				for ci := range rs.chains {
					out := applyChain(rs.chains[ci].Fns, sc, val)
					if len(out) == 0 {
						continue
					}
					idx.prefilte.Scan(out, func(id int32, _ int) bool {
						w := int(id) >> 6
						bits[w] |= 1 << uint(id&63)
						return true
					})
				}
				return true
			})
		}
	}

	// ---- 2) 评估候选 ----
	for i, r := range idx.rules {
		w := i >> 6
		if bits[w]&(1<<uint(i&63)) == 0 {
			continue
		}
		if hit, ok := rs.evalRule(t, r, sc); ok {
			if !emit(hit) {
				return
			}
		}
	}
}

// evalRule 对单条规则求值。链式规则要求**全部成员都命中**才算命中。
func (rs *RuleSet) evalRule(t *tx.Transaction, r *CompiledRule, sc *EvalScratch) (Hit, bool) {
	if len(r.ChainMembers) > 1 {
		return rs.evalChain(t, r, sc)
	}
	return rs.evalRuleSingle(t, r, sc)
}

// evalChain 按顺序评估链条的每个成员，任一不命中即整条不命中。
//
// 报告的是**链首**的 ID/类目/分数（心智模型是"一条规则"），
// 但目标位置取最后一个命中的成员，这样审计里能看到到底卡在哪个条件上。
func (rs *RuleSet) evalChain(t *tx.Transaction, head *CompiledRule, sc *EvalScratch) (Hit, bool) {
	var last Hit
	for _, m := range head.ChainMembers {
		hit, ok := rs.evalRuleSingle(t, m, sc)
		if !ok {
			return Hit{}, false
		}
		last = hit
	}
	return Hit{
		Rule:    head,
		Target:  last.Target,
		Detail:  "chain[" + last.Rule.ID + "]: " + last.Detail,
		Matched: last.Matched,
	}, true
}

// evalRuleSingle 展开 target，逐值跑变换链 + 算子。
func (rs *RuleSet) evalRuleSingle(t *tx.Transaction, r *CompiledRule, sc *EvalScratch) (Hit, bool) {
	for _, plan := range r.Targets {
		matched := false
		var hit Hit
		expandCollection(&t.Vars, plan.Collection, func(key string, val []byte) bool {
			if !targetMatches(plan, key) {
				return true
			}
			out := applyChain(r.Transforms, sc, val)
			res, err := r.Op.Eval(&operator.EvalCtx{
				TxID:   t.ID,
				RuleID: r.ID,
				Phase:  r.Phase,
			}, out)
			if err != nil || !res.Matched {
				return true
			}
			hit = Hit{
				Rule:    r,
				Target:  TargetLabel(plan.Collection, key),
				Detail:  res.Detail,
				Matched: len(out),
			}
			matched = true
			return false
		})
		if matched {
			return hit, true
		}
	}
	return Hit{}, false
}

// applyChain 依次执行变换链。任一变换失败就跳过该变换（用上一步的结果继续），
// 绝不因为"洗不干净"就放弃检测。
func applyChain(fns []TransformFn, sc *EvalScratch, in []byte) []byte {
	if len(fns) == 0 {
		return in
	}
	cur := in
	for _, fn := range fns {
		out, err := fn(cur, kv.Params(nil))
		if err != nil || out == nil {
			continue
		}
		cur = out
	}
	return cur
}

// PhaseRules 返回某阶段启用的规则（只读）。
func (rs *RuleSet) PhaseRules(p tx.Phase) []*CompiledRule {
	idx := rs.phases[int(p)]
	if idx == nil {
		return nil
	}
	return idx.rules
}

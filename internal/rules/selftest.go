package rules

import (
	"fmt"
	"strings"

	"donothack/internal/kv"
	"donothack/internal/operator"
)

// SelfTest 跑每条规则自带的正负样本。
//
// 两条判据（docs/RULES.md §10.1）：
//   - 正样本**必须**命中：否则这条规则是摆设，规则集会给人虚假的安全感。
//   - 负样本**必须不**命中：否则它会误伤正常业务。
//
// 任何一条不满足就返回错误，调用方（control.Apply）会拒绝整批规则并回滚 ——
// 这条闸门是"手滑写了个宽泛正则把线上打挂"的最后一道防线。
func (rs *RuleSet) SelfTest() error {
	var problems []string
	sc := &EvalScratch{}

	for _, r := range rs.allRules {
		if !r.Enabled {
			continue
		}
		for _, pos := range r.Test.Positive {
			if !ruleHits(r, sc, []byte(pos)) {
				problems = append(problems, fmt.Sprintf(
					"%s：正样本没有被命中 —— %q（规则实际不会拦它）", r.Source, truncate(pos)))
			}
		}
		for _, neg := range r.Test.Negative {
			if ruleHits(r, sc, []byte(neg)) {
				problems = append(problems, fmt.Sprintf(
					"%s：负样本被命中了 —— %q（这条规则会误伤正常业务）", r.Source, truncate(neg)))
			}
		}
	}

	if len(problems) == 0 {
		return nil
	}
	head := fmt.Sprintf("自测未通过（%d 处）：", len(problems))
	var sb strings.Builder
	sb.WriteString(head)
	for i, p := range problems {
		if i >= 12 {
			sb.WriteString(fmt.Sprintf("\n  … 还有 %d 处", len(problems)-i))
			break
		}
		sb.WriteString("\n  - " + p)
	}
	return fmt.Errorf("%s", sb.String())
}

// ruleHits 判断一条规则是否命中给定值（走它自己的变换链与算子）。
func ruleHits(r *CompiledRule, sc *EvalScratch, val []byte) bool {
	out := applyChain(r.Transforms, sc, val)
	res, err := r.Op.Eval(&operator.EvalCtx{RuleID: r.ID, Phase: r.Phase}, out)
	if err != nil {
		return false
	}
	return res.Matched
}

// HitsValue 是给 CLI（donothack rules eval）与规则测试台用的公开版本。
func (rs *RuleSet) HitsValue(ruleID, value string) (bool, string, error) {
	r, ok := rs.byID[ruleID]
	if !ok {
		return false, "", fmt.Errorf("规则 %s 不存在", ruleID)
	}
	sc := &EvalScratch{}
	out := applyChain(r.Transforms, sc, []byte(value))
	res, err := r.Op.Eval(&operator.EvalCtx{RuleID: r.ID, Phase: r.Phase}, out)
	if err != nil {
		return false, "", err
	}
	return res.Matched, res.Detail, nil
}

// TraceValue 返回一次求值的完整链路，供"规则测试台"展示：
// 变换前、变换后、算子判定结果。
func (rs *RuleSet) TraceValue(ruleID, value string) (*Trace, error) {
	r, ok := rs.byID[ruleID]
	if !ok {
		return nil, fmt.Errorf("规则 %s 不存在", ruleID)
	}
	sc := &EvalScratch{}
	before := []byte(value)
	after := applyChain(r.Transforms, sc, before)
	res, err := r.Op.Eval(&operator.EvalCtx{RuleID: r.ID, Phase: r.Phase}, after)
	if err != nil {
		return nil, err
	}
	return &Trace{
		RuleID:     r.ID,
		Message:    r.Message,
		Phase:      r.Phase.String(),
		Severity:   r.Severity.String(),
		Category:   r.Category,
		Score:      r.Score,
		Targets:    r.Targets,
		Transforms: r.TransformNames,
		Operator:   r.OperatorName,
		Before:     string(before),
		After:      string(after),
		Matched:    res.Matched,
		Detail:     res.Detail,
	}, nil
}

// Trace 是一次求值的可读记录。**不含 payload 原文以外的敏感处理**：
// 它只服务命令行调试，控制台展示时要走可打印化。
type Trace struct {
	RuleID     string
	Message    string
	Phase      string
	Severity   string
	Category   string
	Score      int
	Targets    []VarPlan
	Transforms []string
	Operator   string
	Before     string
	After      string
	Matched    bool
	Detail     string
}

func truncate(s string) string {
	s = strings.ReplaceAll(s, "\n", "\\n")
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

var _ = kv.Params(nil)

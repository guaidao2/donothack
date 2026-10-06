// Package engine 是检测流水线的调度者：把解析结果喂给规则集，累计评分并给出裁决。
//
// 三条设计约束：
//  1. **数据面只读**：引擎持有的是 atomic.Pointer 指向的不可变 RuleSet，
//     绝不原地修改；热加载由 control 包原子替换。
//  2. **fail-open**：任何解析或规则异常都放行并留痕，绝不因为 WAF 自身错误
//     让业务 5xx（docs/DESIGN.md §16）。
//  3. **惰性**：没有阶段 2 规则时完全不读请求体 —— 省下的是真实的 IO 与 CPU。
package engine

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"

	"donothack/internal/parser"
	"donothack/internal/rules"
	"donothack/internal/tx"
)

// Mode 是运行模式。
type Mode string

const (
	// ModeDetect 只记录不拦截（上线默认）。
	ModeDetect Mode = "detect"
	// ModeBlock 超阈值即拦截。
	ModeBlock Mode = "block"
	// ModeMixed 按类目分别设阈值。
	ModeMixed Mode = "mixed"
)

// Options 是引擎构造参数。
type Options struct {
	RuleSet *rules.RuleSet

	Mode             string
	InboundThreshold int
	// CategoryThresholds 只在 mixed 模式下生效：类目 → 该类的拦截阈值。
	CategoryThresholds map[string]int
	// Categories 是类目默认分（规则没写 score 时用）。
	Categories map[string]int
	// Limits 是解析层上限。
	Limits parser.Limits
	// ExpandNestedDocs 是否做值级文档展开（base64(JSON) 那类）。
	// 有成本，所以在有相关规则时才值得打开。
	ExpandNestedDocs bool

	// CapturePayload 是否把命中位置的"变换前/变换后"值带进事件。
	//
	// 默认关：**日志里永远不写 payload**，这个开关只影响内存事件
	// （控制台详情页与规则测试台用它给人看"到底命中了什么"）。
	// 打开时在入口处做一次可打印化 + 截断，不会因为 10 MB 的 body 撑爆内存。
	CapturePayload bool
}

// Engine 是检测引擎。
type Engine struct {
	rs   atomic.Pointer[rules.RuleSet]
	opts Options
	// exceptions 是控制台维护的例外（与规则文件里的并存）
	exceptions atomic.Pointer[[]*rules.Exception]

	scratchPool sync.Pool
	// parserScratch 池：解析期的解码缓冲（key/val/body/path）。
	// 不池化的话每个请求都要重新分配这六七块切片 —— 那正是"热路径零分配"漏掉的地方。
	parserScratch sync.Pool
}

// New 构造引擎。
func New(o Options) *Engine {
	if o.Limits.MaxParams == 0 {
		o.Limits = parser.DefaultLimits()
	}
	if o.InboundThreshold <= 0 {
		o.InboundThreshold = 5
	}
	if o.Categories == nil {
		o.Categories = rules.DefaultCategories()
	}
	e := &Engine{opts: o}
	e.rs.Store(o.RuleSet)
	e.scratchPool.New = func() any { return &rules.EvalScratch{} }
	e.parserScratch.New = func() any { return &parser.Scratch{} }
	return e
}

// RuleSet 返回当前规则集。
func (e *Engine) RuleSet() *rules.RuleSet { return e.rs.Load() }

// SetExceptions 替换控制台维护的例外列表。
func (e *Engine) SetExceptions(list []*rules.Exception) {
	cp := make([]*rules.Exception, len(list))
	copy(cp, list)
	e.exceptions.Store(&cp)
}

// Swap 原子替换规则集。在途请求继续用旧规则集，新请求用新的。
func (e *Engine) Swap(rs *rules.RuleSet) (old *rules.RuleSet) {
	return e.rs.Swap(rs)
}

// Decision 是一次请求的检测结论。
type Decision struct {
	Verdict tx.Verdict
	Status  int
	Score   int
	RuleID  string
	Reason  string
	Events  []tx.Event
	Mode    string
	// Degraded 记录降级档位（非空表示这次裁决是在降级状态下做出的）。
	Degraded string

	// 下面三个字段来自规则显式声明的 action（不是分数累计出来的）。
	// 它们的使用受模式约束：**detect 模式下一律不拦** ——
	// "只记录"就是只记录，规则不该绕过部署方的上线节奏。
	actionVerdict tx.Verdict
	actionRule    string
	actionStatus  int
	actionBan     bool
}

// 动作优先级：Drop > Block > Tarpit > Challenge > Log > Pass
func actionPriority(v tx.Verdict) int {
	switch v {
	case tx.VerdictDrop:
		return 5
	case tx.VerdictBlock:
		return 4
	case tx.VerdictTarpit:
		return 3
	case tx.VerdictChallenge:
		return 2
	case tx.VerdictLog:
		return 1
	default:
		return 0
	}
}

// verdictForAction 把规则的 action.type 映射成裁决。
func verdictForAction(t string) tx.Verdict {
	switch t {
	case "block":
		return tx.VerdictBlock
	case "challenge":
		return tx.VerdictChallenge
	case "tarpit":
		return tx.VerdictTarpit
	case "drop":
		return tx.VerdictDrop
	default:
		return tx.VerdictLog
	}
}

// Process 跑完整条流水线。
func (e *Engine) Process(ctx context.Context, t *tx.Transaction, req *http.Request) (Decision, error) {
	rs := e.rs.Load()

	// 惰性：没有阶段 2 规则就不读请求体。
	lim := e.opts.Limits
	if rs == nil || len(rs.PhaseRules(tx.PhaseRequestBody)) == 0 {
		lim.MaxInspectBody = 0
	}

	ps := e.parserScratch.Get().(*parser.Scratch)
	defer func() {
		ps.Reset()
		e.parserScratch.Put(ps)
	}()

	// 解析层的 panic 已在 parser 内部兜住；这里再兜一层，
	// 因为规则评估也可能碰到意料之外的输入。
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Vars.AddParseError("引擎 panic")
			}
		}()
		parser.ParseRequest(t, req, ps, lim)
		if e.opts.ExpandNestedDocs {
			parser.ExpandNestedDocs(&t.Vars, ps, lim)
		}
	}()

	dec := Decision{Verdict: tx.VerdictPass, Status: 200, Mode: e.opts.Mode}

	if rs == nil {
		dec.Reason = "规则集尚未加载"
		return dec, nil
	}

	// 例外：命中的例外会禁用指定规则/类目；mode=skip 时整请求不过规则。
	exRes := rs.MatchExceptions(rules.ExceptionInput{
		Path:   t.Vars.Path,
		Method: t.Vars.Method,
		IP:     t.ClientIP,
	})
	// 控制台维护的例外与规则文件里的例外合并判断
	if ex := e.exceptions.Load(); ex != nil && len(*ex) > 0 {
		exRes.Merge(rules.MatchExceptionList(*ex, rules.ExceptionInput{
			Path:   t.Vars.Path,
			Method: t.Vars.Method,
			IP:     t.ClientIP,
		}))
	}
	if exRes.SkipAll {
		dec.Reason = "命中例外（skip）"
		dec.Events = append(dec.Events, tx.Event{
			RuleID:   "EXCEPTION",
			Category: "exception",
			Detail:   "请求命中例外，规则被跳过",
		})
		return dec, nil
	}

	scratch := e.scratchPool.Get().(*rules.EvalScratch)
	defer func() {
		scratch.Reset()
		e.scratchPool.Put(scratch)
	}()

	// 解析异常本身也是信号：解析不了或超出上限的请求值得记分。
	for i, msg := range t.Vars.ParseErrors {
		if i >= 5 {
			break
		}
		t.Score.Add("protocol", 1)
		dec.Events = append(dec.Events, tx.Event{
			Category: "protocol",
			Severity: tx.SevLow,
			Score:    1,
			Target:   "PARSE",
			Operator: "parse_error",
			Detail:   msg,
			Phase:    tx.PhaseRequestBody,
		})
	}

	phases := []tx.Phase{tx.PhaseRequestHeaders, tx.PhaseRequestBody}
	for _, p := range phases {
		stop := e.runPhase(rs, t, p, scratch, exRes, &dec)
		if stop {
			break
		}
	}

	dec.Score = t.Score.Total
	dec.Verdict, dec.Status, dec.RuleID, dec.Reason = e.decide(dec)
	return dec, nil
}

// runPhase 跑一个阶段，返回 true 表示应当终止后续阶段。
func (e *Engine) runPhase(rs *rules.RuleSet, t *tx.Transaction, p tx.Phase, sc *rules.EvalScratch,
	exRes rules.MatchResult, dec *Decision) (stop bool) {

	rs.Match(t, p, sc, func(h rules.Hit) bool {
		r := h.Rule
		if exRes.IsRuleDisabled(r.ID, r.Category) {
			return true
		}
		ev := tx.Event{
			RuleID:     r.ID,
			Phase:      r.Phase,
			Category:   r.Category,
			Severity:   r.Severity,
			Score:      r.Score,
			Target:     h.Target,
			Operator:   r.OperatorName,
			Detail:     h.Detail,
			MatchedLen: h.Matched,
			Truncated:  t.Vars.BodyTruncated,
			HardBlock:  r.HardBlock,
			At:         t.StartedAt,
		}
		if e.opts.CapturePayload {
			ev.PayloadBefore = h.Before
			ev.PayloadAfter = h.After
		}
		t.Score.Add(r.Category, r.Score)
		dec.Events = append(dec.Events, ev)

		// 规则显式声明的动作优先级高于分数累计
		if v := verdictForAction(r.Action.Type); actionPriority(v) > actionPriority(dec.actionVerdict) {
			dec.actionVerdict = v
			dec.actionRule = r.ID
			dec.actionStatus = r.Action.Status
			dec.actionBan = r.Action.BanIP
		}

		if r.HardBlock {
			// hard_block：命中即终止本阶段剩余规则。
			// 注意 detect 模式下仍然只记录 —— 模式是部署方的选择，不该被规则绕过。
			return false
		}
		return true
	})

	// 分数达标、命中 hard_block、或已经拿到 drop/block 类动作就结束本阶段。
	// drop 是最高优先级，遇到就没必要再花 CPU 跑后面的规则。
	for _, ev := range dec.Events {
		if ev.HardBlock {
			return true
		}
	}
	if dec.actionVerdict == tx.VerdictDrop {
		return true
	}
	if t.Score.Total >= e.thresholdFor(t, dec) {
		return true
	}
	return false
}

// thresholdFor 返回当前生效的阈值（mixed 模式下取类目最小阈值）。
func (e *Engine) thresholdFor(t *tx.Transaction, dec *Decision) int {
	if e.opts.Mode != string(ModeMixed) || len(e.opts.CategoryThresholds) == 0 {
		return e.opts.InboundThreshold
	}
	best := 1 << 30
	t.Score.Each(func(category string, score int) bool {
		if th, ok := e.opts.CategoryThresholds[category]; ok && score >= th && th < best {
			best = th
		}
		return true
	})
	if best == 1<<30 {
		return e.opts.InboundThreshold
	}
	return best
}

// decide 把分数与模式翻译成裁决。
func (e *Engine) decide(dec Decision) (tx.Verdict, int, string, string) {
	blocking := Mode(e.opts.Mode) == ModeBlock || Mode(e.opts.Mode) == ModeMixed

	// 1) 规则显式动作优先。detect 模式下一律只记录 ——
	//    "只记录"就是只记录，规则不该绕过部署方的上线节奏。
	if actionPriority(dec.actionVerdict) > actionPriority(tx.VerdictLog) {
		if !blocking {
			return tx.VerdictLog, 200, dec.actionRule,
				"规则动作 " + dec.actionVerdict.String() + "（检测模式：仅记录）"
		}
		status := dec.actionStatus
		if status == 0 {
			if dec.actionVerdict == tx.VerdictDrop {
				status = 0 // drop 直接断连，不写状态码
			} else {
				status = 403
			}
		}
		return dec.actionVerdict, status, dec.actionRule,
			"规则显式动作：" + dec.actionVerdict.String()
	}

	// 2) hard_block 命中即拦（同样受模式约束）
	hardRule := ""
	for _, ev := range dec.Events {
		if ev.HardBlock {
			hardRule = ev.RuleID
			break
		}
	}

	over := dec.Score >= e.opts.InboundThreshold
	if !over && hardRule == "" {
		if len(dec.Events) > 0 {
			return tx.VerdictLog, 200, firstRuleID(dec.Events), "命中但未达阈值（仅记录）"
		}
		return tx.VerdictPass, 200, "", ""
	}

	ruleID := hardRule
	if ruleID == "" {
		ruleID = firstRuleID(dec.Events)
	}

	if blocking {
		if hardRule != "" {
			return tx.VerdictBlock, 403, ruleID, "命中 hard_block 规则"
		}
		return tx.VerdictBlock, 403, ruleID, "分数达到拦截阈值"
	}
	// detect 模式：只记录。这是上线默认值 —— 用真实命中数据决定哪条规则够格进拦截档。
	return tx.VerdictLog, 200, ruleID, "检测模式：仅记录不拦截"
}

func firstRuleID(events []tx.Event) string {
	for _, ev := range events {
		if ev.RuleID != "" {
			return ev.RuleID
		}
	}
	return ""
}

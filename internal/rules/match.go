package rules

import (
	"strconv"
	"strings"

	"donothack/internal/kv"
	"donothack/internal/tx"
)

// Match 在指定阶段评估规则集。
//
// 执行顺序：
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
	//
	// **这里刻意不用回调**：`expandCollection(..., func(...))` 的闭包会捕获
	// bits/sc/rs 并逃逸到堆上，每请求多出几次分配。改成按下标直接迭代
	// （参数类集合走 paramsOf，标量集合走 collectionValues），
	// AC 扫描也改用 ScanBits 直接写位图。
	if idx.prefilter != nil {
		var scalars [2][]byte
		for _, col := range idx.collections {
			if ps, ok := paramsOf(&t.Vars, col); ok {
				// `*_NAMES` 集合扫的是**参数名**（与 evalRuleSingle 同一口径）：
				// 预筛与求值语义必须一致，否则要么规则永不评估、要么命中却不拦。
				names := isNamesCollection(col)
				for i := 0; i < ps.Len(); i++ {
					if names {
						rs.prefilterValue(ps.KeyAt(i), idx, bits, sc)
						continue
					}
					rs.prefilterValue(ps.ValueAt(i), idx, bits, sc)
				}
				continue
			}
			if isFileCollection(col) {
				// 文件类集合可能有很多个文件，**必须全部扫到**。
				// 原先统一走 collectionValues（最多 2 个值），
				// 于是第 3 个上传文件里的 webshell 魔数就进不了预筛。
				rs.prefilterFiles(&t.Vars, col, idx, bits, sc)
				continue
			}
			n := collectionValues(&t.Vars, col, &scalars)
			for i := 0; i < n; i++ {
				rs.prefilterValue(scalars[i], idx, bits, sc)
			}
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

// isFileCollection 判断是否是需要逐项遍历的文件类集合。
func isFileCollection(col string) bool {
	switch col {
	case "FILES", "FILES_NAMES", "FILES_SIZES", "FILES_MAGIC":
		return true
	}
	return false
}

// prefilterFiles 逐项扫描文件类集合（不设 2 个值的上限）。
func (rs *RuleSet) prefilterFiles(v *tx.Collections, col string, idx *phaseIndex, bits []uint64, sc *EvalScratch) {
	switch col {
	case "FILES":
		for _, metas := range v.Files {
			for i := range metas {
				rs.prefilterValue([]byte(metas[i].FileName), idx, bits, sc)
			}
		}
	case "FILES_NAMES":
		for name := range v.Files {
			rs.prefilterValue([]byte(name), idx, bits, sc)
		}
	case "FILES_SIZES":
		for _, metas := range v.Files {
			for i := range metas {
				rs.prefilterValue([]byte(strconv.FormatInt(metas[i].Size, 10)), idx, bits, sc)
			}
		}
	case "FILES_MAGIC":
		for _, metas := range v.Files {
			for i := range metas {
				m := metas[i]
				if m.MagicLen == 0 {
					continue
				}
				rs.prefilterValue(m.Magic[:m.MagicLen], idx, bits, sc)
			}
		}
	}
}

// prefilterValue 把一个值过一遍所有变换链，命中的字面量写进位图。
func (rs *RuleSet) prefilterValue(val []byte, idx *phaseIndex, bits []uint64, sc *EvalScratch) {
	if len(val) == 0 {
		return
	}
	for ci := range rs.chains {
		out := applyChain(rs.chains[ci].Fns, sc, val)
		if len(out) == 0 {
			continue
		}
		idx.prefilter.ScanBits(out, bits)
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
	// **把最后一个成员的命中详情与 payload 带上**：
	// 原先只带 Target/Detail/Matched，于是链式命中在控制台详情页里
	// "变换前/变换后"永远是空的 —— 而链式规则恰恰最需要看是哪一步命中的。
	return Hit{
		Rule:    head,
		Target:  last.Target,
		Detail:  "chain[" + last.Rule.ID + "]: " + last.Detail,
		Matched: last.Matched,
		Before:  last.Before,
		After:   last.After,
	}, true
}

// evalRuleSingle 展开 target，逐值跑变换链 + 算子。
func (rs *RuleSet) evalRuleSingle(t *tx.Transaction, r *CompiledRule, sc *EvalScratch) (Hit, bool) {
	// 上下文复用：这里不给每个规则求值新建对象（见 EvalScratch.ctx 的注释）。
	sc.ctx.TxID = t.ID
	sc.ctx.RuleID = r.ID
	sc.ctx.Phase = r.Phase

	for _, plan := range r.Targets {
		// 直接迭代而不是传回调：回调闭包会捕获局部变量并逃逸到堆上，
		// 每条规则每个目标一次分配 —— 在"零分配"的门禁下这是致命的。
		ps, isParams := paramsOf(&t.Vars, plan.Collection)
		if isParams {
			// `*_NAMES` 集合（ARGS_NAMES / REQUEST_HEADERS_NAMES / …）按语义
			// 匹配的是**参数名**，不是参数值。
			// 原先这里一律取 ValueAt —— 于是 `targets: ARGS_NAMES` 配
			// `pm: ["id"]` 会去匹配任何**值**里含 "id" 的参数，语义反了。
			names := isNamesCollection(plan.Collection)
			for i := 0; i < ps.Len(); i++ {
				key := ps.KeyAt(i)
				if !targetMatches(plan, key) {
					continue
				}
				val := ps.ValueAt(i)
				if names {
					val = key
				}
				out := applyChain(r.Transforms, sc, val)
				res, err := r.Op.Eval(&sc.ctx, out)
				if err != nil || !res.Matched {
					continue
				}
				return Hit{
					Rule:    r,
					Target:  TargetLabel(plan.Collection, string(key)),
					Detail:  res.Detail,
					Matched: len(out),
					Before:  val,
					After:   out,
				}, true
			}
			continue
		}
		// 标量集合（URI / 方法 / 地址…）：逐个显式取值，同样不引入闭包。
		if hit, ok := rs.evalScalar(t, r, plan, sc); ok {
			return hit, true
		}
	}
	return Hit{}, false
}

// isNamesCollection 判断集合是否是"只看参数名"的那一类。
//
// 它们与对应参数集合共用同一份 tx.Params 存储，但**语义不同**：
// 匹配的是 key 而不是 value（见 evalRuleSingle 里的用法）。
func isNamesCollection(col string) bool {
	return strings.HasSuffix(col, "_NAMES")
}

// evalScalar 处理不是 tx.Params 的集合。
func (rs *RuleSet) evalScalar(t *tx.Transaction, r *CompiledRule, plan VarPlan, sc *EvalScratch) (Hit, bool) {
	// 标量集合的键几乎总是空串或 "(raw)"，这里的转换不在热路径上
	// （热路径是参数类集合的按下标迭代，见 evalRuleSingle）。
	try := func(key string, val []byte) (Hit, bool) {
		if !targetMatchesString(plan, key) {
			return Hit{}, false
		}
		out := applyChain(r.Transforms, sc, val)
		res, err := r.Op.Eval(&sc.ctx, out)
		if err != nil || !res.Matched {
			return Hit{}, false
		}
		return Hit{
			Rule:    r,
			Target:  TargetLabel(plan.Collection, key),
			Detail:  res.Detail,
			Matched: len(out),
			Before:  val,
			After:   out,
		}, true
	}

	switch plan.Collection {
	case "REQUEST_URI":
		return try("", []byte(t.Vars.URI))
	case "REQUEST_PATH":
		// 双形态：原始路径与规范化路径都要过检测。
		if t.Vars.RawPath != "" {
			if h, ok := try("(raw)", []byte(t.Vars.RawPath)); ok {
				return h, true
			}
		}
		return try("", []byte(t.Vars.Path))
	case "REQUEST_METHOD":
		return try("", []byte(t.Vars.Method))
	case "REQUEST_PROTOCOL":
		return try("", []byte(t.Vars.Proto))
	case "REQUEST_BODY":
		if t.Vars.Body == nil {
			return Hit{}, false
		}
		return try("", t.Vars.Body)
	case "REMOTE_ADDR":
		return try("", []byte(t.Vars.RawIP))
	case "ARGS_COUNT":
		return try("", []byte(strconv.Itoa(t.Vars.Args.Len())))
	case "REQUEST_URI_LENGTH":
		return try("", []byte(strconv.Itoa(len(t.Vars.URI))))
	case "REQUEST_BODY_LENGTH":
		return try("", []byte(strconv.Itoa(len(t.Vars.Body))))
	case "FILES":
		for _, metas := range t.Vars.Files {
			for i := range metas {
				if h, ok := try(metas[i].FieldName, []byte(metas[i].FileName)); ok {
					return h, true
				}
			}
		}
	case "FILES_NAMES":
		for name := range t.Vars.Files {
			if h, ok := try(name, []byte(name)); ok {
				return h, true
			}
		}
	case "FILES_SIZES":
		for _, metas := range t.Vars.Files {
			for i := range metas {
				if h, ok := try(metas[i].FieldName, []byte(strconv.FormatInt(metas[i].Size, 10))); ok {
					return h, true
				}
			}
		}
	case "FILES_MAGIC":
		for _, metas := range t.Vars.Files {
			for i := range metas {
				m := metas[i]
				if m.MagicLen == 0 {
					continue
				}
				if h, ok := try(m.FieldName, m.Magic[:m.MagicLen]); ok {
					return h, true
				}
			}
		}
	}
	return Hit{}, false
}

// paramsOf 返回集合对应的 tx.Params（不是参数类集合时返回 false）。
//
// 有了它，规则求值可以**直接按下标迭代**而不必传回调闭包 ——
// 闭包会让捕获的局部变量逃逸，每条规则一次分配。
func paramsOf(v *tx.Collections, collection string) (*tx.Params, bool) {
	switch collection {
	case "ARGS":
		return &v.Args, true
	case "ARGS_GET":
		return &v.ArgsGet, true
	case "ARGS_POST":
		return &v.ArgsPost, true
	case "ARGS_JSON":
		return &v.ArgsJSON, true
	case "ARGS_XML":
		return &v.ArgsXML, true
	case "ARGS_NAMES":
		return &v.Args, true
	case "REQUEST_HEADERS":
		return &v.Headers, true
	case "REQUEST_HEADERS_NAMES":
		return &v.Headers, true
	case "REQUEST_COOKIES":
		return &v.Cookies, true
	case "REQUEST_COOKIES_NAMES":
		return &v.Cookies, true
	}
	return nil, false
}

// applyChain 依次执行变换链。任一变换失败就跳过该变换（用上一步的结果继续），
// 绝不因为"洗不干净"就放弃检测。
//
// 输出缓冲来自 sc 的双缓冲 arena（零分配）；返回值**只在下一次 applyChain 之前有效**，
// 需要留存必须自己拷贝（`engine` 在记录事件 payload 时就做了拷贝）。
func applyChain(fns []TransformFn, sc *EvalScratch, in []byte) []byte {
	if len(fns) == 0 {
		return in
	}
	cur := in
	for _, fn := range fns {
		// 交替使用两块缓冲：下一步的输出绝不能覆盖上一步的输入
		// （而它正是下一步的输入）。
		slot := sc.slot ^ 1
		dst := sc.reserve(slot, len(cur))
		out, err := fn(dst, cur, kv.Params(nil))
		if err != nil || out == nil {
			continue
		}
		// **只把"确实写在我们缓冲里"的结果存回 arena。**
		//
		// 变换在"无需改动"时会直接返回入参（`return in, nil`），而那个 in 指向
		// **事务的参数缓冲**。无条件存回就会让 arena 引用一块不属于它的内存，
		// 下一次往 arena 写就把参数覆盖掉 —— 真踩过：参数被链输出改坏，
		// 预筛因此看到错的值而静默漏检（base64(JSON) 那条回归测试抓到的）。
		if usedDst(dst, out) {
			sc.arena[slot] = out
		}
		sc.slot = slot
		cur = out
	}
	return cur
}

// usedDst 判断 out 是否就是 dst 那块缓冲（按起始地址比较，不需要 unsafe）。
//
// 之所以可靠：调用方已经用 reserve 把容量备到了 len(cur)，变换的
// `append(dst[:0], in...)` 不会重新分配，结果必然从 dst 的起始地址开始。
func usedDst(dst, out []byte) bool {
	d := dst[:cap(dst)]
	if len(d) == 0 || len(out) == 0 {
		return false
	}
	return &d[0] == &out[0]
}

// PhaseRules 返回某阶段启用的规则（只读）。
func (rs *RuleSet) PhaseRules(p tx.Phase) []*CompiledRule {
	idx := rs.phases[int(p)]
	if idx == nil {
		return nil
	}
	return idx.rules
}

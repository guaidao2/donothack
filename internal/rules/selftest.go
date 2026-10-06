package rules

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"donothack/internal/kv"
	"donothack/internal/operator"
	"donothack/internal/tx"
)

// SelfTest 跑每条规则自带的正负样本。
//
// 两条判据：
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
		// **链成员不单独测**：它们不参与阶段索引（只在链首求值时一起判），
		// 单独灌一个成员的条件永远不可能命中 —— 那会误报成"正样本没命中"。
		// 链的合法性由链首那一条（带 ChainMembers 的那条）覆盖。
		if r.chainMember {
			continue
		}
		for _, pos := range r.Test.Positive {
			// **走完整路径（含预筛）**，不是只跑算子。
			//
			// 预筛的语义是"字面量没命中就跳过这条规则"，所以字面量提错的规则
			// 在生产里永远不会被评估 —— 而只跑算子的自测一定会说"命中"。
			// 实测受害者：PROBE-2001（量词体 `{2,10}` 被当成字面量 "2,10"），
			// 正样本 `1999*1999` 生产里 score=0、零事件，却通过了闸门。
			if !rs.selfTestHits(r, sc, pos, true) {
				problems = append(problems, fmt.Sprintf(
					"%s：正样本没有被命中 —— %q（规则实际不会拦它）", r.Source, truncate(pos)))
			}
		}
		for _, neg := range r.Test.Negative {
			if rs.selfTestHits(r, sc, neg, false) {
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

// ruleHits 判断一条规则是否命中给定值（**只跑变换链与算子，不经过预筛**）。
//
// 注意：**自测不要用这个函数** —— 它挡不住"预筛字面量提错导致规则永不评估"。
// 保留它是给"只想验算子行为"的调用方（例如单测）用的。
func ruleHits(r *CompiledRule, sc *EvalScratch, val []byte) bool {
	out := applyChain(r.Transforms, sc, val)
	res, err := r.Op.Eval(&operator.EvalCtx{RuleID: r.ID, Phase: r.Phase}, out)
	if err != nil {
		return false
	}
	return res.Matched
}

// selfTestHits 用样本构造一个最小事务，跑**完整的 Match**（含预筛），
// 判断指定规则是否被命中。
//
// 为什么必须这么做：预筛是生产路径的一部分，而"字面量提取错误"这类 bug
// 只有在预筛参与时才会暴露（表现为规则永远不被评估）。
// 样本会被灌进规则可能用到的每一个集合（路径、各参数集合、头、Cookie、文件、body），
// 这样无论规则声明的是哪个集合都能被喂到。
func (rs *RuleSet) selfTestHits(r *CompiledRule, sc *EvalScratch, sample string, positive bool) bool {
	tr := &tx.Transaction{}
	v := &tr.Vars

	// 链式规则：要求**所有成员同时命中**，所以要把每个成员各自的样本一起灌进去。
	//
	// 两个细节都不能省（都踩过）：
	//   - 只灌一个成员会必然误报"正样本没命中"；
	//   - 测某个成员的**负样本**时，必须把那个成员的样本换成负样本、
	//     其余成员仍用各自的正样本 —— 否则链总是命中，负样本会被误报成"误伤"。
	if len(r.ChainMembers) > 1 {
		for _, m := range r.ChainMembers {
			// **归属必须按极性判断**：同一个字符串可能既是 A 的正样本、又是 B 的负样本
			// （链式规则里很常见，例如 "chunked" 是 TE 的正样本、却是 CL 的负样本）。
			// 只按值找会认错成员，正样本就会被误报成"没命中"。
			var owned []string
			if positive {
				owned = m.Test.Positive
			} else {
				owned = m.Test.Negative
			}
			s := ""
			if containsSample(owned, sample) {
				s = sample
			} else if len(m.Test.Positive) > 0 {
				s = m.Test.Positive[0]
			}
			if s != "" {
				feedSample(v, m, s)
			}
		}
	} else {
		feedSample(v, r, sample)
	}

	hit := false
	rs.Match(tr, r.Phase, sc, func(h Hit) bool {
		if h.Rule != nil && h.Rule.ID == r.ID {
			hit = true
			return false // 提前结束
		}
		return true
	})
	return hit
}

// targetsCollection 判断规则是否声明了某个目标集合。
func targetsCollection(r *CompiledRule, col string) bool {
	for _, plan := range r.Targets {
		if plan.Collection == col {
			return true
		}
	}
	return false
}

// containsSample 判断样本是否在列表里（链式规则要靠它定位样本属于哪个成员）。
func containsSample(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// feedSample 把一个样本灌进事务里"这条规则会读到的那些集合"。
//
// 两类集合要分开处理（这是写这个 harness 时踩过的坑）：
//
//  1. **参数类集合**（ARGS / HEADERS / COOKIES / JSON / XML）：按规则自己声明的
//     target 填，并且用它的 selector 当参数名 —— 否则声明了
//     `selector: transfer-encoding` 的规则会因为参数名不对而误报"没命中"。
//  2. **派生标量集合**（`*_LENGTH`、`ARGS_COUNT`）：样本是**那个数值本身**，
//     不是原始输入。例如 `PROTO-1001`（URI 长度 > 8191）的正样本是 "9000" ——
//     直接把它当 URI 只会得到长度 4。所以这里按样本数值**合成对应规模的输入**。
func feedSample(v *tx.Collections, r *CompiledRule, sample string) {
	val := []byte(sample)

	// 参数类集合
	for _, plan := range r.Targets {
		key := plan.Selector
		if key == "" {
			key = "selftest"
		}
		if ps, ok := paramsOf(v, plan.Collection); ok {
			if isNamesCollection(plan.Collection) {
				// `*_NAMES` 匹配的是**参数名**：样本必须当 key 喂进去，
				// 否则自测会误报"正样本没命中"。
				ps.Add(val, []byte("1"))
				continue
			}
			ps.Add([]byte(key), val)
		}
	}
	// 合并视图与其余参数集合也各放一份（规则可能直接对着 ARGS 匹配）
	for _, ps := range []*tx.Params{&v.Args, &v.ArgsGet, &v.ArgsPost, &v.ArgsJSON, &v.ArgsXML,
		&v.Headers, &v.Cookies} {
		if ps.Len() == 0 {
			ps.Add([]byte("selftest"), val)
		}
	}

	// 请求行与标量集合（样本直接当值）
	v.Method = sample
	v.URI = sample
	v.RawPath = sample
	v.Path = sample
	v.Query = sample
	v.Proto = sample
	v.Host = sample
	v.RawIP = sample
	v.Body = val

	// 派生集合：按数值合成输入，让"长度/个数"类规则也能被真实地喂到
	if n, err := strconv.Atoi(strings.TrimSpace(sample)); err == nil && n > 0 && n <= 1<<20 {
		for _, plan := range r.Targets {
			switch plan.Collection {
			case "REQUEST_URI_LENGTH":
				v.URI = strings.Repeat("a", n)
				v.Path = v.URI
				v.RawPath = v.URI
			case "REQUEST_BODY_LENGTH":
				v.Body = bytes.Repeat([]byte("a"), n)
			case "ARGS_COUNT":
				for i := 0; i < n && i < 2000; i++ {
					v.Args.Add([]byte("p"+strconv.Itoa(i)), []byte("1"))
				}
			}
		}
	}

	// 文件集合（FILES / FILES_NAMES / FILES_SIZES / FILES_MAGIC）
	if v.Files == nil {
		v.Files = tx.FileSet{}
	}
	// **魔数用十六进制表达**：FILES_MAGIC 是二进制，YAML 写不出原始高字节
	// （`\x90` 会变成 UTF-8 两字节），所以约定样本是十六进制，这里解码成真实字节。
	// 否则自测喂进去的是"十六进制文本的字节"，而生产里是原始魔数 —— 自测又变成自欺。
	magic := val
	if targetsCollection(r, "FILES_MAGIC") {
		if decoded, err := hex.DecodeString(strings.TrimSpace(sample)); err == nil && len(decoded) > 0 {
			magic = decoded
		}
	}
	meta := tx.FileMeta{FieldName: "selftest", FileName: sample, Size: int64(len(magic))}
	n := copy(meta.Magic[:], magic)
	meta.MagicLen = n
	v.Files["selftest"] = []tx.FileMeta{meta}
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

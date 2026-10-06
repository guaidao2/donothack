package rules

import (
	"testing"

	"donothack/internal/tx"
)

// 的回归：`*_NAMES` 集合必须匹配**参数名**，不是参数值。
//
// 原先 `evalRuleSingle` 对这个集合也取 `ValueAt(i)`，于是
// `targets: ARGS_NAMES` + `pm: ["id"]` 会去匹配任何**值**里含 "id" 的参数 ——
// 语义完全反了：规则作者想找"名叫 id 的参数"，实际却在找"值里含 id 的参数"。
func TestNamesCollectionMatchesKeys(t *testing.T) {
	const body = `
version: 1
meta:
  name: names
  author: test
rules:
  - id: T-NAME
    phase: 1
    severity: low
    category: scanner
    message: "参数名探测"
    targets:
      - collection: ARGS_NAMES
    transforms: [lowercase]
    operator:
      name: pm
      params: {patterns: ["hack"]}
    test:
      # 正样本是**参数名**
      positive: ["hack"]
      negative: ["normal", "another normal"]
`
	rs, err := loadOne(t, body, true)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	sc := &EvalScratch{}

	matches := func(name, value string) bool {
		tr := &tx.Transaction{}
		tr.Vars.ArgsGet.Add([]byte(name), []byte(value))
		tr.Vars.Args.Add([]byte(name), []byte(value))
		hit := false
		rs.Match(tr, tx.PhaseRequestHeaders, sc, func(h Hit) bool {
			if h.Rule != nil && h.Rule.ID == "T-NAME" {
				hit = true
				return false
			}
			return true
		})
		return hit
	}

	// 参数名里有 "hack" → 必须命中
	if !matches("hack", "whatever") {
		t.Error("参数名含 hack 时必须命中（ARGS_NAMES 匹配的是名字）")
	}
	// 只有**值**里有 "hack" → 不该命中（这正是修复前的错误行为）
	if matches("normal", "hack") {
		t.Error("只有参数值含 hack 时不该命中 —— 那说明 ARGS_NAMES 又按值匹配了")
	}
	// 都不含 → 不命中
	if matches("normal", "value") {
		t.Error("名字与值都不含 hack 时不该命中")
	}
}

// 预筛与求值的口径必须一致：否则要么规则永不评估、要么命中却不拦。
func TestNamesCollectionPrefilterUsesKeys(t *testing.T) {
	const body = `
version: 1
meta:
  name: names2
  author: test
rules:
  - id: T-NAME2
    phase: 1
    severity: low
    category: scanner
    message: "参数名探测"
    targets:
      - collection: REQUEST_HEADERS_NAMES
    transforms: [lowercase]
    operator:
      name: pm
      params: {patterns: ["x-hack"]}
    test:
      positive: ["x-hack"]
      negative: ["normal", "another normal"]
`
	rs, err := loadOne(t, body, true)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	sc := &EvalScratch{}

	check := func(header, value string, want bool) {
		tr := &tx.Transaction{}
		tr.Vars.Headers.Add([]byte(header), []byte(value))
		got := false
		rs.Match(tr, tx.PhaseRequestHeaders, sc, func(h Hit) bool {
			if h.Rule != nil && h.Rule.ID == "T-NAME2" {
				got = true
				return false
			}
			return true
		})
		if got != want {
			t.Errorf("头名=%q 值=%q：期望命中=%v，实际=%v（预筛与求值口径不一致？）",
				header, value, want, got)
		}
	}

	check("x-hack", "1", true)       // 名字命中
	check("normal", "x-hack", false) // 只有值命中 → 不该命中
}

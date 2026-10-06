package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 的回归测试：**提取出来的字面量必须是"必然出现在匹配文本里"的**。
//
// 旧实现的错法是把正则语法当成字面量：
//
//	^[0-9]{2,10}...$  →  "2,10"（量词体）
//	(?:abc)def        →  ":abc"（组前缀的 '?' 和 ':'）
//	[^]]union         →  "]union"（取反类后那个字面量 ']' 被当成类结束）
//
// 后果不是"少命中一点"，而是**规则永远不会被评估**（预筛要求输入含那个不可能出现的串）。
// 所以这里断言的是**噪声字符不出现**，而不是精确等于某个串 ——
// 提取器允许提出更短/更长的合法字面量（尽可以让它优化），只不允许提出语法字符。
func TestExtractedLiteralHasNoRegexSyntax(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		forbid  []string
		wantAny []string // 若非空，提取结果必须包含其中之一
	}{
		// 那个真实受害者：量词体绝不能被提成字面量
		{"量词体", `^[0-9]{2,10}\s*[*+\-/]\s*[0-9]{2,10}$`, []string{"2,10", ",", "{", "}"}, nil},
		// 组前缀 ':' 不能进字面量；"abc" 本身是必须出现的，允许（甚至更好）
		{"非捕获组", `(?:abc)def`, []string{":abc", "?:"}, nil},
		// 取反类后面那个 ']' 是字面量，不能和后面的字一起被提出来
		{"取反类", `[^]]union`, []string{"]union", "^]"}, nil},
		// 正常字面量照常提出
		{"普通", `union\s+select`, []string{"\\", "s+"}, []string{"select", "union"}},
	}
	for _, c := range cases {
		got := longestLiteralInPattern(c.pattern)
		for _, bad := range c.forbid {
			if strings.Contains(got, bad) {
				t.Errorf("%s：提取结果 %q 里含语法字符 %q（pattern=%s）—— 这会让规则变成死规则",
					c.name, got, bad, c.pattern)
			}
		}
		if len(c.wantAny) > 0 {
			ok := false
			for _, w := range c.wantAny {
				if got == w {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s：期望提到 %v 之一，实际 %q", c.name, c.wantAny, got)
			}
		}
	}
}

// 结构性看门人：**每一条出厂规则的每个正样本**都必须能在完整路径（含预筛）下命中。
//
// 这条比单测某条规则值钱 —— 它挡住的是"字面量提错 ⇒ 规则静默失效"这**一整类**问题。
// PROBE-2001 就是这样活过整个 P6 验收的（自测与规则测试台都绕过预筛，说它命中）。
func TestEveryShippedRulePositiveIsReachable(t *testing.T) {
	matches, err := filepath.Glob("../../rules/*.yaml")
	if err != nil || len(matches) == 0 {
		t.Fatalf("找不到出厂规则文件：%v（glob 结果 %d 个）", err, len(matches))
	}
	rs, err := LoadFiles(DefaultOptions(), matches)
	if err != nil {
		t.Fatalf("加载出厂规则集失败：%v", err)
	}
	if len(rs.Rules()) < 10 {
		t.Fatalf("出厂规则集只加载到 %d 条，明显不对", len(rs.Rules()))
	}

	sc := &EvalScratch{}
	dead := 0
	for _, r := range rs.Rules() {
		if !r.Enabled {
			continue
		}
		for _, sample := range r.Test.Positive {
			if !rs.selfTestHits(r, sc, sample, true) {
				dead++
				t.Errorf("规则 %s 的正样本 %q 在完整路径下没有命中（疑似死规则：字面量提取或目标集合有问题）",
					r.ID, sample)
			}
		}
		if dead > 12 {
			t.Fatal("死规则太多，先停下（后面的不再列）")
		}
	}
	if dead == 0 {
		t.Logf("出厂 %d 条规则的正样本全部能被预筛打到", len(rs.Rules()))
	}
}

// 自测 harness 要覆盖各类集合：路径、头、文件。
func TestSelfTestHarnessCoversAllCollections(t *testing.T) {
	yaml := `
version: 1
meta: {name: harness, author: test}
rules:
  - id: T-PATH
    phase: 1
    severity: low
    category: scanner
    message: "path"
    targets: [{collection: REQUEST_PATH}]
    transforms: [lowercase]
    operator: {name: pm, params: {patterns: ["selftest"]}}
    test: {positive: ["selftest"], negative: ["nothing here", "another normal one"]}
  - id: T-HEADER
    phase: 1
    severity: low
    category: scanner
    message: "header"
    targets: [{collection: REQUEST_HEADERS, selector: "user-agent"}]
    transforms: [lowercase]
    operator: {name: pm, params: {patterns: ["selftest"]}}
    test: {positive: ["selftest"], negative: ["nothing here", "another normal one"]}
  - id: T-FILES
    phase: 2
    severity: low
    category: scanner
    message: "files"
    targets: [{collection: FILES}]
    transforms: [lowercase]
    operator: {name: pm, params: {patterns: ["selftest"]}}
    test: {positive: ["selftest"], negative: ["nothing here", "another normal one"]}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "harness.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	rs2, err := LoadFiles(DefaultOptions(), []string{path})
	if err != nil {
		t.Fatalf("三集合规则集应当加载通过（自测要覆盖到这些集合）：%v", err)
	}
	if len(rs2.Rules()) != 3 {
		t.Fatalf("期望 3 条规则，实际 %d", len(rs2.Rules()))
	}
}

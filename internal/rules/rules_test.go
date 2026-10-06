package rules

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"donothack/internal/parser"
	"donothack/internal/tx"
)

// writeRules 把测试规则写到 .tmp/test/rules-p2 下（项目约定：测试产物放 .tmp/test）。
func writeRules(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("建目录失败：%v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("写规则文件失败：%v", err)
	}
	return p
}

// loadOne 加载单个规则文件（关闭自测，用于测试结构校验本身）。
func loadOne(t *testing.T, body string, selfTest bool) (*RuleSet, error) {
	t.Helper()
	p := writeRules(t, "one.yaml", body)
	opts := DefaultOptions()
	opts.SelfTest = selfTest
	return LoadFiles(opts, []string{p})
}

const minimalRule = `
version: 1
meta:
  name: test
rules:
  - id: TEST-1
    phase: 2
    severity: high
    category: sqli
    message: "测试"
    targets:
      - collection: ARGS
    transforms: [removeComments, urlDecode, lowercase]
    operator:
      name: detectSQLi
    test:
      positive: ["1' union select 1,2--", "admin' or '1'='1"]
      negative: ["it's a good day", "select your country"]
`

func TestLoadValidRuleSet(t *testing.T) {
	rs, err := loadOne(t, minimalRule, true)
	if err != nil {
		t.Fatalf("应当加载成功：%v", err)
	}
	st := rs.Stats()
	if st.Rules != 1 || st.Enabled != 1 {
		t.Errorf("规则统计 = %+v", st)
	}
	if rs.Version == "" {
		t.Error("规则集版本不能为空（要进审计）")
	}
}

// 未知名字必须整批拒绝：部分加载会制造"以为有 500 条规则其实只有 300 条"的缺口。
func TestLoadRejectsUnknownNames(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			"未知变换",
			strings.Replace(minimalRule, "transforms: [removeComments, urlDecode, lowercase]",
				"transforms: [removeComments, urlDecodee]", 1),
			"未注册的变换",
		},
		{
			"未知算子",
			strings.Replace(minimalRule, "name: detectSQLi", "name: detectSQLiX", 1),
			"未知算子",
		},
		{
			"未知集合",
			strings.Replace(minimalRule, "collection: ARGS", "collection: ARGUMENTS", 1),
			"未知集合",
		},
		{
			"响应侧集合",
			strings.Replace(minimalRule, "collection: ARGS", "collection: RESPONSE_BODY", 1),
			"本轮不实现响应检测",
		},
		{
			"未知类目",
			strings.Replace(minimalRule, "category: sqli", "category: sqlii", 1),
			"不在允许的类目里",
		},
		{
			"非法阶段",
			strings.Replace(minimalRule, "phase: 2", "phase: 9", 1),
			"phase=9 非法",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadOne(t, c.body, true)
			if err == nil {
				t.Fatal("应当被拒绝")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("报错信息应包含 %q，实际：%v", c.want, err)
			}
		})
	}
}

// 没有正负样本的规则必须被拒绝：没有样本的规则改了也没人能验证。
func TestLoadRequiresTestSamples(t *testing.T) {
	noTest := strings.Replace(minimalRule, `
    test:
      positive: ["1' union select 1,2--", "admin' or '1'='1"]
      negative: ["it's a good day", "select your country"]
`, "", 1)
	if _, err := loadOne(t, noTest, true); err == nil || !strings.Contains(err.Error(), "必须同时带 test.positive") {
		t.Errorf("缺样本应当被拒绝，实际：%v", err)
	}

	oneNeg := strings.Replace(minimalRule, `negative: ["it's a good day", "select your country"]`,
		`negative: ["it's a good day"]`, 1)
	if _, err := loadOne(t, oneNeg, true); err == nil || !strings.Contains(err.Error(), "至少要 2 条") {
		t.Errorf("负样本不足应当被拒绝，实际：%v", err)
	}
}

// 自测闸门：负样本被命中（会误伤业务）必须拒绝加载。
func TestSelfTestRejectsFalsePositive(t *testing.T) {
	bad := strings.Replace(minimalRule, `negative: ["it's a good day", "select your country"]`,
		`negative: ["1' union select 9,9--", "select your country"]`, 1)
	_, err := loadOne(t, bad, true)
	if err == nil {
		t.Fatal("负样本被命中时必须拒绝加载")
	}
	if !strings.Contains(err.Error(), "负样本被命中") {
		t.Errorf("报错应指出负样本被命中，实际：%v", err)
	}
}

// 自测闸门：正样本不命中（规则是摆设）也必须拒绝加载。
func TestSelfTestRejectsDeadRule(t *testing.T) {
	bad := strings.Replace(minimalRule, `positive: ["1' union select 1,2--", "admin' or '1'='1"]`,
		`positive: ["totally benign text here"]`, 1)
	_, err := loadOne(t, bad, true)
	if err == nil {
		t.Fatal("正样本不命中时必须拒绝加载")
	}
	if !strings.Contains(err.Error(), "正样本没有被命中") {
		t.Errorf("报错应指出正样本未命中，实际：%v", err)
	}
}

// 规则 ID 必须全局唯一，否则审计里的历史记录会对不上。
func TestLoadRejectsDuplicateID(t *testing.T) {
	// 同一个 rules 列表里放两条同 ID 规则
	dup := `
version: 1
meta:
  name: dup
rules:
  - id: TEST-1
    phase: 2
    severity: high
    category: sqli
    message: "第一条"
    targets: [{collection: ARGS}]
    operator: {name: contains, params: {value: "union"}}
    test:
      positive: ["union"]
      negative: ["select", "insert"]
  - id: TEST-1
    phase: 2
    severity: high
    category: xss
    message: "第二条用了同一个 ID"
    targets: [{collection: ARGS}]
    operator: {name: contains, params: {value: "script"}}
    test:
      positive: ["script"]
      negative: ["style", "link"]
`
	p := writeRules(t, "dup.yaml", dup)
	_, err := LoadFiles(DefaultOptions(), []string{p})
	if err == nil || !strings.Contains(err.Error(), "重复") {
		t.Errorf("重复 ID 应当被拒绝，实际：%v", err)
	}
}

// ---------------------------------------------------------------- 链式规则

const chainRule = `
version: 1
meta:
  name: chain-test
rules:
  - id: CHAIN-1
    phase: 1
    chain: true
    severity: medium
    category: protocol
    score: 4
    message: "有 TE"
    targets:
      - collection: REQUEST_HEADERS
        selector: "transfer-encoding"
    operator:
      name: contains
      params: {value: "chunked"}
    test:
      positive: ["chunked"]
      negative: ["gzip", "identity"]
  - id: CHAIN-2
    phase: 1
    severity: high
    category: protocol
    score: 1
    message: "有 CL"
    targets:
      - collection: REQUEST_HEADERS
        selector: "content-length"
    operator:
      name: regex
      params: {pattern: "^[0-9]{1,12}$"}
    test:
      positive: ["42", "0"]
      negative: ["chunked", "abc"]
`

// 链式规则：只有**全部成员**都命中才算命中。
//
// 这条判据直接决定误报量：如果把链条拆成两条独立规则，
// 前一半（"有 TE"）会在每个带 TE 的请求上加 4 分。
func TestChainRequiresAllMembers(t *testing.T) {
	rs, err := loadOne(t, chainRule, true)
	if err != nil {
		t.Fatalf("链式规则应当加载成功：%v", err)
	}

	head, ok := rs.Rule("CHAIN-1")
	if !ok {
		t.Fatal("找不到链首")
	}
	if len(head.ChainMembers) != 2 {
		t.Fatalf("链首应有 2 个成员，实际 %d", len(head.ChainMembers))
	}
	if head.Chain {
		t.Error("chain 标记应在编译期被消费掉")
	}
	// 成员不能单独进索引（否则会被当成独立规则评估）
	for _, r := range rs.PhaseRules(tx.PhaseRequestHeaders) {
		if r.ID == "CHAIN-2" {
			t.Error("链条成员不该单独出现在阶段规则里")
		}
	}

	sc := &EvalScratch{}
	// 只有 TE：链条不成立
	if _, hit := rs.evalRule(buildTx(t, map[string]string{"transfer-encoding": "chunked"}), head, sc); hit {
		t.Error("只有 TE 时链条不该命中")
	}
	// 只有 CL：链条不成立
	if _, hit := rs.evalRule(buildTx(t, map[string]string{"content-length": "42"}), head, sc); hit {
		t.Error("只有 CL 时链条不该命中")
	}
	// 两个都有：命中
	if _, hit := rs.evalRule(buildTx(t, map[string]string{
		"transfer-encoding": "chunked", "content-length": "42",
	}), head, sc); !hit {
		t.Error("两个条件都满足时链条应当命中")
	}
}

// 链成员被禁用会让链条永远不命中 —— 必须在加载期就报错，而不是线上静默失效。
func TestChainRejectsDisabledMember(t *testing.T) {
	bad := strings.Replace(chainRule, "  - id: CHAIN-2\n    phase: 1",
		"  - id: CHAIN-2\n    enabled: false\n    phase: 1", 1)
	if _, err := loadOne(t, bad, false); err == nil || !strings.Contains(err.Error(), "被禁用") {
		t.Errorf("链成员被禁用应当报错，实际：%v", err)
	}
}

// 链首没有后续成员 → 配置错误。
func TestChainRequiresMember(t *testing.T) {
	bad := strings.Replace(chainRule, "  - id: CHAIN-2\n", "  - id: OTHER-2\n    phase: 99\n", 1)
	_ = bad
	head := `
version: 1
meta:
  name: t
rules:
  - id: CHAIN-1
    phase: 1
    chain: true
    severity: low
    category: protocol
    message: "x"
    targets: [{collection: REQUEST_HEADERS}]
    operator: {name: unconditionalMatch}
    test:
      positive: ["a"]
      negative: ["b", "c"]
`
	if _, err := loadOne(t, head, false); err == nil || !strings.Contains(err.Error(), "没有成员规则") {
		t.Errorf("链首缺少成员应当报错，实际：%v", err)
	}
}

// ---------------------------------------------------------------- 预筛安全

// 预筛是"没命中字面量就跳过这条规则"，所以提取字面量必须谨慎：
// 含交替 `|` 的正则只能提一个最长字面量，输入可能只命中别的分支 → 会漏检。
func TestPrefilterRefusesUnsafeRegex(t *testing.T) {
	unsafe := []string{
		`\.(?:git|svn|hg)/`,          // 交替
		`\.(?:php|jsp)\.[a-z]{2,6}$`, // 交替 + 可选量词
		`(abc)?def`,
		`(abc)*x`,
		`a{0,3}bc`,
	}
	for _, pat := range unsafe {
		if _, ok := regexLiteralCandidateSafe(pat, 3); ok {
			t.Errorf("正则 %q 不该被判定为可预筛（会造成漏检）", pat)
		}
	}

	safe := map[string]string{
		`\bunion\b\s+select`: "union",
		`union[ ]+select`:    "union",
		`acunetix-wvs-test`:  "acunetix-wvs-test",
		`<script[^>]*>`:      "script",
	}
	for pat, want := range safe {
		got, ok := regexLiteralCandidateSafe(pat, 3)
		if !ok {
			t.Errorf("正则 %q 应当可预筛", pat)
			continue
		}
		if want != "" && !strings.Contains(pat, want) {
			t.Errorf("用例自身写错了：%q 不含 %q", pat, want)
		}
		if len(got) < 3 {
			t.Errorf("正则 %q 提取出的字面量 %q 太短", pat, got)
		}
	}
}

// 端到端：带交替的正则规则必须仍能被预筛选中（通过 alwaysRun 路径）。
func TestAlternationRuleStillFires(t *testing.T) {
	body := `
version: 1
meta:
  name: alt
rules:
  - id: ALT-1
    phase: 1
    severity: high
    category: scanner
    score: 5
    message: "dotfile"
    targets:
      - collection: REQUEST_PATH
    transforms: [lowercase]
    operator:
      name: regex
      params:
        pattern: "(?:^|/)\\.(?:git|svn|env)(?:/|\\.|$)"
    test:
      positive: ["/.git/config", "/.env"]
      negative: ["/assets/app.js", "/.well-known/acme"]
`
	rs, err := loadOne(t, body, true)
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if rs.Stats().NoLiteralRules != 1 {
		t.Errorf("带交替的正则应被归入'必须每请求评估'，统计 = %+v", rs.Stats())
	}

	tr := buildTxPath(t, "/.git/config")
	var hits []string
	sc := &EvalScratch{}
	rs.Match(tr, tx.PhaseRequestHeaders, sc, func(h Hit) bool {
		hits = append(hits, h.Rule.ID)
		return true
	})
	if len(hits) == 0 {
		t.Error("/.git/config 必须命中（预筛漏检的回归测试）")
	}
}

// ---------------------------------------------------------------- 辅助

func buildTx(t *testing.T, headers map[string]string) *tx.Transaction {
	t.Helper()
	return buildTxFull(t, "/", nil, headers)
}

func buildTxPath(t *testing.T, path string) *tx.Transaction {
	t.Helper()
	return buildTxFull(t, path, nil, nil)
}

func buildTxFull(t *testing.T, path string, query map[string]string, headers map[string]string) *tx.Transaction {
	t.Helper()
	url := path
	if len(query) > 0 {
		var parts []string
		for k, v := range query {
			parts = append(parts, k+"="+v)
		}
		url += "?" + strings.Join(parts, "&")
	}
	req := httptest.NewRequest("GET", url, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	tr := &tx.Transaction{}
	tr.ClientIP = "127.0.0.1"
	parser.ParseRequest(tr, req, &parser.Scratch{}, parser.DefaultLimits())
	return tr
}

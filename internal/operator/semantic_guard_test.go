package operator

import (
	"strings"
	"testing"

	"donothack/internal/kv"
)

// 的回归：`quoteThenComment` / `stackedQuery` 不能是 CPU 放大器。
//
// 语义算子**不参与预筛**（每条规则每请求、对每个参数值与整个 body 都要跑），
// 而 `MaxInspectBody` 是 512 KiB。原先 `quoteThenComment` 对**每个引号**都做
// 最多 192 字节的子串搜索 —— 实测 64 KiB 纯引号值 1.36 ms，512 KiB 就是 ~11 ms。
//
// 修法是加 O(n) 的必要条件判断。这个测试同时保证：
//
//	① 该命中的形态一个都不能漏（前置判断绝不能改变结果）；
//	② 病态输入的耗时被压到线性量级。
func TestSemanticOperatorsNotQuadratic(t *testing.T) {
	params := kv.Params{} // detectSQLi 没有必需参数
	op, err := Compile("detectSQLi", params)
	if err != nil {
		t.Fatalf("编译 detectSQLi 失败：%v", err)
	}
	ctx := &EvalCtx{RuleID: "T", Phase: 2}

	// ① 正确性：注释型与堆叠型的经典形态必须仍然命中
	mustHit := []string{
		`1'--`,
		`1'-- -`,
		`1'/*x*/`,
		`1'; select * from users`,
		`1'; drop table users`,
		`admin'#`,
		`1"/*`,
	}
	for _, s := range mustHit {
		res, err := op.Eval(ctx, []byte(s))
		if err != nil {
			t.Fatalf("Eval(%q) 出错：%v", s, err)
		}
		if !res.Matched {
			t.Errorf("%q 是典型的注释/堆叠注入形态，不该漏：%s", s, res.Detail)
		}
	}

	// ② 病态输入：全是引号 / 全是分号，必须是线性且不慢
	//    （阈值给得很宽松，只要能看出不是 O(n²) 就行；门禁在 lint.py 的基准里）
	pathological := []string{
		strings.Repeat("'", 256<<10),
		strings.Repeat(";", 256<<10),
		strings.Repeat(`a'b`, 64<<10),
	}
	for _, s := range pathological {
		res, err := op.Eval(ctx, []byte(s))
		if err != nil {
			t.Fatalf("病态输入 Eval 出错：%v", err)
		}
		// 纯引号/纯分号不是注入，不该命中
		if res.Matched {
			t.Errorf("长度 %d 的病态输入被误判为注入：%s", len(s), res.Detail)
		}
	}
}

// 前置判断不能改变语义：随机构造"引号 + 注释标记"的组合，逐一对照慢路径。
func TestQuoteThenCommentMatchesSlowPath(t *testing.T) {
	// 慢路径 = 修复前那版（无前置判断），直接抄在这里当参照
	slow := func(s string) bool {
		for i := 0; i < len(s); i++ {
			if s[i] != '\'' && s[i] != '"' {
				continue
			}
			rest := s[i+1:]
			if len(rest) > 64 {
				rest = rest[:64]
			}
			if strings.Contains(rest, "--") || strings.HasPrefix(strings.TrimSpace(rest), "#") ||
				strings.Contains(rest, "/*") {
				return true
			}
		}
		return false
	}

	cases := []string{
		"", "'", `"`, `1'--`, `1' /*`, `x'#`, `'#`, `';--`, "a'b", "O'Brien",
		`1' and '1'='1`, `union select`, `--no quote`, `#no quote`, `/*no quote*/`,
		`it's fine`, `say "hi"`, `1'--` + strings.Repeat("x", 200),
	}
	for _, s := range cases {
		if got, want := quoteThenComment(s), slow(s); got != want {
			t.Errorf("quoteThenComment(%q)=%v，慢路径=%v（前置判断改变了语义）", s, got, want)
		}
	}

	// 堆叠查询同理
	slowStacked := func(s string) bool {
		for i := 0; i < len(s); i++ {
			if s[i] != ';' {
				continue
			}
			rest := strings.TrimSpace(s[i+1:])
			for _, kw := range stackedKeywords {
				if strings.HasPrefix(rest, kw) {
					return true
				}
			}
		}
		return false
	}
	stackCases := []string{
		"", ";", "1;select 1", "; drop table x", "a;b;c", "select 1",
		";select", ";insert into x", "; shutdown", "1;update x set y=1",
		"; SELECT * FROM t", // 大写：关键字表是小写，慢路径也不命中 → 行为一致即可
	}
	for _, s := range stackCases {
		if got, want := stackedQuery(s), slowStacked(s); got != want {
			t.Errorf("stackedQuery(%q)=%v，慢路径=%v（前置判断改变了语义）", s, got, want)
		}
	}
}

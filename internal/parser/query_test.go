package parser

import (
	"testing"

	"donothack/internal/tx"
)

// 热路径零分配是硬门禁（docs/PERFORMANCE.md §3.1）。
// 这条测试比任何注释都可靠：一旦有人往 query 解析里塞了 map 或 strings.Split，
// 这里立刻红。
func TestParseQueryZeroAlloc(t *testing.T) {
	lim := DefaultLimits()
	p := &tx.Params{}
	sc := &Scratch{}
	raw := "a=1&b=2&c=%2Fetc%2Fpasswd&user=admin&id=42&q=hello+world&empty=&novalue"

	avg := testing.AllocsPerRun(500, func() {
		p.Reset()
		sc.Reset()
		ParseQueryInto(p, sc, raw, lim)
	})
	if avg != 0 {
		t.Fatalf("query 解析必须零分配，实测 %.2f allocs/op", avg)
	}
}

func TestParseQueryBasics(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	ParseQueryInto(&p, sc, "user=ad%6din&pass=a+b&empty=&novalue&x=%2Fetc%2Fpasswd", lim)

	cases := map[string]string{
		"user":    "admin",       // %6d → m
		"pass":    "a b",         // '+' 当空格
		"empty":   "",            // 空值要保留（?id= 是有意义的）
		"novalue": "",            // 无 '=' 的键
		"x":       "/etc/passwd", // 解码后
	}
	for k, want := range cases {
		got, ok := p.Get(k)
		if !ok {
			t.Errorf("缺少参数 %q", k)
			continue
		}
		if string(got) != want {
			t.Errorf("%s = %q，期望 %q", k, got, want)
		}
	}
}

// HPP（HTTP 参数污染）：同名参数必须**全部**保留。
//
// crackweb 明确用了这个手法：payload 作为同名参数的第二次出现发送，
// 只读第一个取值的过滤器看不到它，而取最后一个取值的框架会执行它。
func TestParseQueryKeepsAllValuesForHPP(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	ParseQueryInto(&p, sc, "id=1&id=2'%20OR%201=1--&id=3", lim)

	if p.Len() != 3 {
		t.Fatalf("同名参数应全部保留，实际 %d 个", p.Len())
	}
	// 只取第一个：这正是"会被绕过"的用法，所以规则侧必须用 ForEachValue
	first, _ := p.Get("id")
	if string(first) != "1" {
		t.Errorf("Get 应返回第一个值，得到 %q", first)
	}
	// 全部取值都要能看到
	var all []string
	p.ForEachValue("id", func(v []byte) bool {
		all = append(all, string(v))
		return true
	})
	if len(all) != 3 {
		t.Fatalf("ForEachValue 应看到 3 个取值，实际 %d 个：%v", len(all), all)
	}
	if all[1] != "2' OR 1=1--" {
		t.Errorf("第二个取值 = %q，payload 必须能看见", all[1])
	}
}

// ';' 也当分隔符：不同后端处理不一致，我们多切一刀是安全方向。
func TestParseQueryTreatsSemicolonAsSeparator(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	ParseQueryInto(&p, sc, "a=1;b=2&c=3", lim)
	for _, k := range []string{"a", "b", "c"} {
		if _, ok := p.Get(k); !ok {
			t.Errorf("缺少参数 %q（分号应作为分隔符）", k)
		}
	}
}

func TestParseQueryTruncatesByLimit(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxParams = 3
	var p tx.Params
	sc := &Scratch{}
	ParseQueryInto(&p, sc, "a=1&b=2&c=3&d=4&e=5", lim)

	if p.Len() != 3 {
		t.Errorf("参数个数应被限制为 3，实际 %d", p.Len())
	}
	if !p.Truncated() {
		t.Error("因为上限丢弃参数时必须标记 Truncated")
	}
}

func TestParseQueryTruncatesLongValue(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxParamValLen = 8
	var p tx.Params
	sc := &Scratch{}
	ParseQueryInto(&p, sc, "a=0123456789abcdef", lim)
	v, _ := p.Get("a")
	if len(v) != 8 {
		t.Errorf("值长度应被截断为 8，实际 %d", len(v))
	}
	if !p.TooLong() {
		t.Error("截断值时必须标记 TooLong")
	}
}

// 非法转义原样保留：不能因为解码失败就丢弃内容 —— 那会给攻击者制造
// "WAF 看到的与后端不同" 的机会。
func TestParseQueryKeepsInvalidEscapes(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	ParseQueryInto(&p, sc, "a=%ZZ&b=100%&c=%41", lim)
	if v, _ := p.Get("a"); string(v) != "%ZZ" {
		t.Errorf("非法转义应原样保留，得到 %q", v)
	}
	if v, _ := p.Get("b"); string(v) != "100%" {
		t.Errorf("截断的转义应原样保留，得到 %q", v)
	}
	if v, _ := p.Get("c"); string(v) != "A" {
		t.Errorf("%%41 应解码为 A，得到 %q", v)
	}
}

func TestParseCookiesKeepsAllValues(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	ParseCookiesInto(&p, "session=abc; csrf=xyz; session=evil", sc, lim)
	if p.Len() != 3 {
		t.Fatalf("cookie 个数 = %d，期望 3", p.Len())
	}
	n := 0
	p.ForEachValue("session", func(v []byte) bool { n++; return true })
	if n != 2 {
		t.Errorf("同名 cookie 应全部保留，实际 %d 个", n)
	}
}

func TestParseHeadersLowercasesNames(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	ParseHeadersInto(&p, map[string][]string{
		"User-Agent":      {"crackweb/1.6.4"},
		"X-Forwarded-For": {"1.2.3.4"},
	}, sc, lim)

	if _, ok := p.Get("user-agent"); !ok {
		t.Error("头部名必须小写归一（规则侧只写小写）")
	}
	if v, _ := p.Get("x-forwarded-for"); string(v) != "1.2.3.4" {
		t.Errorf("XFF 值 = %q", v)
	}
}

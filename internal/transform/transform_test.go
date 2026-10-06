package transform

import (
	"bytes"
	"testing"

	"donothack/internal/kv"
)

func apply(t *testing.T, name string, in string, p kv.Params) string {
	t.Helper()
	fn, ok := Lookup(name)
	if !ok {
		t.Fatalf("变换 %q 未注册", name)
	}
	out, err := fn([]byte(in), p)
	if err != nil {
		t.Fatalf("变换 %q 对 %q 报错：%v", name, in, err)
	}
	return string(out)
}

func TestDecodeTransforms(t *testing.T) {
	cases := []struct {
		transform string
		in        string
		want      string
	}{
		// 一次编码
		{"urlDecode", "%2Fetc%2Fpasswd", "/etc/passwd"},
		{"urlDecode", "a%27b", "a'b"},
		// 双写编码：crackweb 的第 2 代就是"一次结构改写套一层编码"
		{"doubleUrlDecode", "%2527", "'"},
		{"doubleUrlDecode", "%253Cscript%253E", "<script>"},
		// IIS 风格 %uXXXX
		{"urlDecodeUni", "%u003Cscript%u003E", "<script>"},
		// HTML 实体
		{"htmlEntityDecode", "&#60;script&#62;", "<script>"},
		{"htmlEntityDecode", "&#x3c;img src=x&#x3e;", "<img src=x>"},
		{"htmlEntityDecode", "&lt;script&gt;", "<script>"},
		{"htmlEntityDecode", "a &amp;&amp; b", "a && b"},
		// JS 转义
		{"jsDecode", `\u003cscript\u003e`, "<script>"},
		{"jsDecode", `\x3cscript\x3e`, "<script>"},
		{"jsDecode", `\u{3c}script\u{3e}`, "<script>"},
		// SQL hex
		{"sqlHexDecode", "0x554e494f4e", "UNION"},
		{"sqlHexDecode", "X'554e494f4e'", "UNION"},
		// base64
		{"base64Decode", "PHNjcmlwdD4=", "<script>"},
		{"base64DecodeExt", "PHNjcmlwdD4", "<script>"}, // 缺 padding + URL-safe
		// hex
		{"hexDecode", "554e494f4e", "UNION"},
		// CSS 转义
		{"cssDecode", `\3c script\3e `, "<script>"},
		// C 风格转义
		{"escapeSeqDecode", `a\nb`, "a\nb"},
		// 注释分割（crackweb 的"结构改写"第一条）
		{"removeComments", "UN/**/ION SE/**/LECT", "UNION SELECT"},
		{"removeComments", "1' -- comment\nOR 1=1", "1' OR 1=1"},
		{"removeComments", "<!-- x --><script>", "<script>"},
		{"replaceComments", "UN/**/ION", "UN ION"}, // 替换成空格，避免拼接出新关键字
		// 空白
		{"compressWhitespace", "a\t\t  b\n\nc", "a b c"},
		{"removeWhitespace", "a b\tc", "abc"},
		{"removeNulls", "a\x00b", "ab"},
		{"trim", "  x  ", "x"},
		// 大小写
		{"lowercase", "SeLeCt", "select"},
		{"uppercase", "select", "SELECT"},
		// length
		{"length", "abcd", "4"},
		// 路径
		{"normalizePath", "/a/../etc/passwd", "/etc/passwd"},
		{"normalizePath", "/a//b///c", "/a/b/c"},
		{"normalizePathWin", `/a\..\b`, "/b"},
		{"normalizePath", "/%2e%2e/etc/passwd", "/etc/passwd"},
	}
	for _, c := range cases {
		t.Run(c.transform+"/"+c.in, func(t *testing.T) {
			if got := apply(t, c.transform, c.in, nil); got != c.want {
				t.Errorf("%s(%q) = %q，期望 %q", c.transform, c.in, got, c.want)
			}
		})
	}
}

// 变换失败必须返回原值，不能报错中断评估。
func TestTransformFailureReturnsInput(t *testing.T) {
	for _, name := range []string{"base64Decode", "base64DecodeExt", "hexDecode", "sqlHexDecode"} {
		got := apply(t, name, "!!!not-decodable!!!", nil)
		if got == "" {
			t.Errorf("%s 失败时应返回原值，得到空串", name)
		}
	}
}

// 任何输入都不许 panic，也不许报错。
func TestAllTransformsSurviveGarbage(t *testing.T) {
	inputs := []string{"", "\x00\x01\x02", "%", "%2", "&&&&", "\\\\\\", "/*", "<!--", "0x", "\xff\xfe"}
	for _, name := range Names() {
		fn, _ := Lookup(name)
		for _, in := range inputs {
			if _, err := fn([]byte(in), nil); err != nil {
				t.Errorf("变换 %s 对 %q 报错：%v", name, in, err)
			}
		}
	}
}

// 变换不得原地修改入参 —— 入参可能是共享的 body 切片。
func TestTransformsDoNotMutateInput(t *testing.T) {
	src := []byte("UN/**/ION SeLeCt")
	orig := append([]byte(nil), src...)
	for _, name := range Names() {
		fn, _ := Lookup(name)
		_, _ = fn(src, nil)
		if !bytes.Equal(src, orig) {
			t.Errorf("变换 %s 修改了入参：%q → %q", name, orig, src)
		}
	}
}

// 组合链：这是 crackweb 第 2 代的典型形态 ——
// 注释分割 + 大小写混淆 + 双写编码，三层叠在一起。
func TestCombinedChainDefeatsLayeredEvasion(t *testing.T) {
	raw := "1%2527%20UN/**/ION%20Se/**/LeCt%201,2--"
	chain := []string{"doubleUrlDecode", "removeComments", "lowercase"}

	cur := []byte(raw)
	for _, name := range chain {
		fn, _ := Lookup(name)
		out, err := fn(cur, nil)
		if err != nil {
			t.Fatalf("链路中 %s 报错：%v", name, err)
		}
		cur = out
	}
	got := string(cur)
	if !bytes.Contains(cur, []byte("union")) || !bytes.Contains(cur, []byte("select")) {
		t.Errorf("组合链没能还原出 union/select，得到 %q", got)
	}
	if !bytes.Contains(cur, []byte("1' ")) {
		t.Errorf("双写编码的引号没被还原，得到 %q", got)
	}
}

func TestSuggestion(t *testing.T) {
	if s := Suggestion("urldecode"); s != "urlDecode" {
		t.Errorf("大小写写错时应建议 urlDecode，得到 %q", s)
	}
	if s := Suggestion("urldecodee"); s != "urlDecode" {
		t.Errorf("多打一个字母时应建议 urlDecode，得到 %q", s)
	}
	if s := Suggestion("完全不相关的东西"); s != "" {
		t.Errorf("差太远时不该乱建议，得到 %q", s)
	}
}

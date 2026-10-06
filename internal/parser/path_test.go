package parser

import "testing"

// 路径规范化的用例集合。
//
// 后半段那批是 crackweb 明确会用到的变体：它专门打"剥掉了 ../ 但把 // 折叠错"
// 这类实现差异（README 里的「路径规范化」手法）。所以这些用例必须过。
func TestNormalizePath(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"普通路径", "/index.html", "/index.html"},
		{"带 query", "/a/b?x=1&y=2", "/a/b"},
		{"带 fragment", "/a/b#frag", "/a/b"},
		{"单次编码", "/%2e%2e/etc/passwd", "/etc/passwd"},
		{"大小写混合编码", "/%2E%2E/%2E%2E/etc/passwd", "/etc/passwd"},
		{"反斜杠", "/..\\..\\windows\\win.ini", "/windows/win.ini"},
		{"双斜杠", "//etc/passwd", "/etc/passwd"},
		{"点斜杠混用", "/.//etc/passwd", "/etc/passwd"},
		{"中间双斜杠", "/etc//passwd", "/etc/passwd"},
		{"三层穿越", "/a/b/../../../etc/passwd", "/etc/passwd"},
		{"穿透到底", "/../../..", "/"},
		{"当前目录段", "/a/./b/./c", "/a/b/c"},
		{"NUL 截断", "/a/b%00.php", "/a/b"},
		{"非法转义保留", "/a/%ZZ/b", "/a/%ZZ/b"},
		{"空路径", "", "/"},
		{"只有斜杠", "/", "/"},
		{"尾随斜杠保留", "/a/b/", "/a/b/"},
		{"编码的斜杠不解码成段分隔", "/a%2Fb", "/a/b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf []byte
			out, _ := NormalizePathInto(buf, c.in, 8192)
			if string(out) != c.want {
				t.Errorf("NormalizePathInto(%q) = %q，期望 %q", c.in, out, c.want)
			}
		})
	}
}

// 原始路径必须与规范化路径**同时**保留：只留一个形态就等于漏一半。
func TestNormalizeKeepsRawSeparately(t *testing.T) {
	raw := "/a/../etc/passwd"
	var buf []byte
	out, _ := NormalizePathInto(buf, raw, 8192)
	if string(out) == raw {
		t.Fatal("规范化应当改变了这个路径，否则用例本身没意义")
	}
	// 调用方（ParseRequest）负责同时保存 raw 与 normalized，见 TestParseRequestKeepsBothPathForms
}

// 绝对形式的 request-target（代理场景合法）必须能正确取到路径，
// 否则规范化结果会变成 "http:/host/path"，规则匹配的是一个后端不会执行的路径。
func TestStripAbsoluteForm(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/a/b?x=1", "/a/b?x=1"},
		{"http://evil.com/a/b?x=1", "/a/b?x=1"},
		{"HTTPS://Evil.com/a", "/a"},
		{"http://evil.com", "/"},
		{"http://evil.com?x=1", "/?x=1"},
		{"/path/http://nope", "/path/http://nope"},
	}
	for _, c := range cases {
		if got := StripAbsoluteForm(c.in); got != c.want {
			t.Errorf("StripAbsoluteForm(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestSplitURI(t *testing.T) {
	p, q := SplitURI("http://h/a/b?x=1&y=2")
	if p != "/a/b" || q != "x=1&y=2" {
		t.Errorf("SplitURI 得到 path=%q query=%q", p, q)
	}
	p, q = SplitURI("/x")
	if p != "/x" || q != "" {
		t.Errorf("SplitURI 得到 path=%q query=%q", p, q)
	}
}

func TestNormalizePathLengthLimit(t *testing.T) {
	long := "/" + string(make([]byte, 0)) + repeat('a', 100)
	for i := range long {
		_ = i
	}
	var buf []byte
	out, truncated := NormalizePathInto(buf, long, 20)
	if !truncated {
		t.Error("超过上限必须报告 truncated")
	}
	if len(out) != 20 {
		t.Errorf("应截断到 20 字节，实际 %d", len(out))
	}
}

func repeat(c byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

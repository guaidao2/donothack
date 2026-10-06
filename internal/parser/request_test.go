package parser

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"donothack/internal/tx"
)

func parseTestRequest(t *testing.T, method, target, body string, ct string, hdrs map[string]string) *tx.Transaction {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	tr := &tx.Transaction{}
	sc := &Scratch{}
	ParseRequest(tr, req, sc, DefaultLimits())
	return tr
}

// 原始路径与规范化路径必须同时保留。
//
// 攻击者专门利用"WAF 规范化方式与后端不一致"：我们必须把两种形态都送去检测，
// 而不是只留一个。
func TestParseRequestKeepsBothPathForms(t *testing.T) {
	// 用源形式（真实服务端看到的 RequestURI 就是这种）
	tr := parseTestRequest(t, "GET", "/a/../etc/passwd?x=1", "", "", nil)
	if tr.Vars.RawPath != "/a/../etc/passwd" {
		t.Errorf("原始路径 = %q", tr.Vars.RawPath)
	}
	if tr.Vars.Path != "/etc/passwd" {
		t.Errorf("规范化路径 = %q", tr.Vars.Path)
	}
	if tr.Vars.Query != "x=1" {
		t.Errorf("query = %q", tr.Vars.Query)
	}
}

// 绝对形式的 request-target（代理场景）走一遍完整解析，不能把 host 当路径。
func TestParseRequestAbsoluteForm(t *testing.T) {
	tr := parseTestRequest(t, "GET", "http://evil.example/a/../etc/passwd?q=1", "", "", nil)
	if tr.Vars.RawPath != "/a/../etc/passwd" {
		t.Errorf("原始路径 = %q", tr.Vars.RawPath)
	}
	if tr.Vars.Path != "/etc/passwd" {
		t.Errorf("规范化路径 = %q", tr.Vars.Path)
	}
	if v, ok := tr.Vars.ArgsGet.Get("q"); !ok || string(v) != "1" {
		t.Errorf("query 参数 q = %q ok=%v", v, ok)
	}
}

// ARGS 必须是所有来源的合并视图：规则只查 GET 的话，payload 放进 JSON body 就绕过了。
func TestParseRequestMergesAllSources(t *testing.T) {
	req := httptest.NewRequest("POST", "http://x/api?fromQuery=1", strings.NewReader(`{"fromJson":"2","nested":{"deep":"3"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "fromCookie=4")
	req.Header.Set("X-Custom", "fromHeader")

	tr := &tx.Transaction{}
	ParseRequest(tr, req, &Scratch{}, DefaultLimits())

	for _, want := range []string{"fromQuery", "fromJson", "nested.deep"} {
		if _, ok := tr.Vars.Args.Get(want); !ok {
			t.Errorf("ARGS 合并视图里缺少 %q；实际：%s", want, dumpKeys(&tr.Vars.Args))
		}
	}
	// cookie 与 header 是独立集合（不并入 ARGS，但规则可以显式指向它们）
	if _, ok := tr.Vars.Cookies.Get("fromCookie"); !ok {
		t.Error("Cookie 集合缺失")
	}
	if _, ok := tr.Vars.Headers.Get("x-custom"); !ok {
		t.Error("Headers 集合缺失（键应小写）")
	}
}

func TestParseRequestFormBody(t *testing.T) {
	tr := parseTestRequest(t, "POST", "http://x/login", "user=admin&pass=p%40ss", "application/x-www-form-urlencoded", nil)
	if v, ok := tr.Vars.ArgsPost.Get("user"); !ok || string(v) != "admin" {
		t.Errorf("表单参数 user = %q ok=%v", v, ok)
	}
	if v, ok := tr.Vars.Args.Get("pass"); !ok || string(v) != "p@ss" {
		t.Errorf("合并视图里的 pass = %q ok=%v", v, ok)
	}
}

// 任何畸形输入都不许 panic，且必须留痕（fail-open 但不静默）。
func TestParseRequestSurvivesGarbage(t *testing.T) {
	cases := []struct {
		name   string
		target string
		body   string
		ct     string
	}{
		{"空目标", "http://x/", "", ""},
		{"超长 URI", "http://x/" + strings.Repeat("a", 20000), "", ""},
		{"残缺 JSON", "http://x/", `{"a":`, "application/json"},
		{"畸形 multipart", "http://x/", "not-a-multipart", "multipart/form-data; boundary=xyz"},
		{"畸形 XML", "http://x/", `<a><b>`, "application/xml"},
		{"二进制 body", "http://x/", "\x00\x01\x02\xff\xfe", "application/octet-stream"},
		{"超深 JSON", "http://x/", strings.Repeat(`{"a":`, 100) + "1" + strings.Repeat("}", 100), "application/json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := parseTestRequest(t, "POST", c.target, c.body, c.ct, nil)
			if tr.Vars.Path == "" {
				t.Error("路径不该为空")
			}
			// 只要没 panic 就算过；有异常必须记在 ParseErrors 里
		})
	}
}

func TestParseRequestRecordsParseErrors(t *testing.T) {
	tr := parseTestRequest(t, "POST", "http://x/", `{"a":`, "application/json", nil)
	if len(tr.Vars.ParseErrors) == 0 {
		t.Error("残缺 JSON 必须留下 parse_error（fail-open 不等于静默）")
	}
}

func TestExpandNestedDocsFindsBase64Payload(t *testing.T) {
	// 内层文档经 base64 包装，外层是普通表单字段
	inner := `{"id":"1' UNION SELECT password FROM users--"}`
	outer := strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D").Replace(b64(inner))

	tr := parseTestRequest(t, "POST", "http://x/save", "payload="+outer, "application/x-www-form-urlencoded", nil)
	sc := &Scratch{}
	ExpandNestedDocs(&tr.Vars, sc, DefaultLimits())

	found := false
	tr.Vars.ArgsJSON.ForEach(func(_, v []byte) bool {
		if bytes.Contains(v, []byte("UNION SELECT")) {
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Errorf("base64 文档里的 payload 应被展开进 ARGS_JSON；实际：%s", dumpKeys(&tr.Vars.ArgsJSON))
	}
}

func b64(s string) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	b := []byte(s)
	for i := 0; i < len(b); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], b[i:])
		sb.WriteByte(tbl[chunk[0]>>2])
		sb.WriteByte(tbl[(chunk[0]&0x03)<<4|chunk[1]>>4])
		if n > 1 {
			sb.WriteByte(tbl[(chunk[1]&0x0f)<<2|chunk[2]>>6])
		} else {
			sb.WriteByte('=')
		}
		if n > 2 {
			sb.WriteByte(tbl[chunk[2]&0x3f])
		} else {
			sb.WriteByte('=')
		}
	}
	return sb.String()
}

// ---- fuzz ----
//
// 正常 `go test` 会跑下面的种子；CI 里另跑 `go test -fuzz` 各 60s。
// 目标很简单：**任何输入都不许 panic**。

func FuzzNormalizePath(f *testing.F) {
	for _, s := range []string{
		"/", "/a/b", "/a/../b", "//etc/passwd", "/%2e%2e/", "/.//x",
		"/a%00b", "/..\\..\\w", "/%ZZ", strings.Repeat("../", 50),
	} {
		f.Add(s)
	}
	var buf []byte
	f.Fuzz(func(t *testing.T, s string) {
		out, _ := NormalizePathInto(buf[:0], s, 8192)
		if len(out) == 0 {
			t.Errorf("规范化结果不应为空路径（输入 %q）", s)
		}
	})
}

func FuzzParseQuery(f *testing.F) {
	for _, s := range []string{
		"a=1", "a=1&a=2", "a=%41", "a=%ZZ", "=x", "&&&", "a", "a=1;b=2",
		"a=" + strings.Repeat("x", 5000),
	} {
		f.Add(s)
	}
	lim := DefaultLimits()
	p := &tx.Params{}
	sc := &Scratch{}
	f.Fuzz(func(t *testing.T, s string) {
		p.Reset()
		sc.Reset()
		ParseQueryInto(p, sc, s, lim)
	})
}

func FuzzParseRequest(f *testing.F) {
	f.Add("GET", "/a?b=1", "", "")
	f.Add("POST", "/api", `{"a":"b"}`, "application/json")
	f.Add("POST", "/x", "a=1&b=2", "application/x-www-form-urlencoded")
	f.Add("POST", "/x", "<?xml version=\"1.0\"?><a>x</a>", "application/xml")
	f.Add("POST", "/x", "garbage", "multipart/form-data; boundary=q")

	f.Fuzz(func(t *testing.T, method, target, body, ct string) {
		req := httptest.NewRequest("POST", "/", strings.NewReader(body))
		req.Method = method
		req.RequestURI = target
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		tr := &tx.Transaction{}
		ParseRequest(tr, req, &Scratch{}, DefaultLimits())
	})
}

// ---- benchmark ----

// 门禁基准：query 解析必须 0 allocs/op（`go test -bench . -benchmem`）。
func BenchmarkParseQuery(b *testing.B) {
	lim := DefaultLimits()
	p := &tx.Params{}
	sc := &Scratch{}
	raw := "a=1&b=2&c=%2Fetc%2Fpasswd&user=admin&id=42&q=hello+world&x=%E4%B8%AD%E6%96%87"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Reset()
		sc.Reset()
		ParseQueryInto(p, sc, raw, lim)
	}
}

// 参考基准：整请求解析（含路径、头部、JSON body）。这里允许分配，
// 但要把数字钉住，防止以后悄悄退化。
func BenchmarkParseRequestJSON(b *testing.B) {
	lim := DefaultLimits()
	body := `{"user":{"name":"admin","tags":["a","b","c"]},"id":42,"note":"hello world"}`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "http://x/api/v1/items?page=2&size=20", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
		req.Header.Set("Cookie", "session=abc; csrf=xyz")
		tr := &tx.Transaction{}
		ParseRequest(tr, req, &Scratch{}, lim)
	}
}

func BenchmarkNormalizePath(b *testing.B) {
	var buf []byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, _ = NormalizePathInto(buf[:0], "/a/../b//c/%2e%2e/d?x=1", 8192)
	}
}

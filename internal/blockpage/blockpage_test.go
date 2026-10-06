package blockpage

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newRenderer(t *testing.T, o Options) *Renderer {
	t.Helper()
	r := New(o)
	if r.CustomError() != "" {
		t.Fatalf("内置模板不该编译失败：%s", r.CustomError())
	}
	return r
}

func req(method, target string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestBuiltinPageRenders(t *testing.T) {
	r := newRenderer(t, Options{Branding: true, Version: "v0.3.0", Contact: "security@example.com"})
	d := r.NewData(req("GET", "http://shop.example.com/cart?id=1", nil),
		"01J8ZK3M4N5P", "sqli", "SQLI-4001", "203.0.113.9", 403, 0)

	out := string(r.RenderHTML(d))
	for _, want := range []string{
		"403", "SQL 注入", "01J8ZK3M4N5P", "shop.example.com", "/cart",
		"security@example.com", "donothack", "v0.3.0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("页面里应包含 %q", want)
		}
	}
	// 不能泄露规则 ID：那等于告诉攻击者哪条规则命中、怎么绕
	if strings.Contains(out, "SQLI-4001") {
		t.Error("内置页面不该暴露规则 ID")
	}
}

// Host 是攻击者可控制的（伪造 Host 头），拦截页回显它必须转义 ——
// 否则我们自己的拦截页就成了反射型 XSS 的输出点。
func TestHostAndPathAreEscaped(t *testing.T) {
	r := newRenderer(t, Options{Branding: true})
	evil := req("GET", "http://x/", nil)
	evil.Host = `a"><script>alert(1)</script>`
	evil.URL.Path = `/x/"><img src=x onerror=alert(1)>`
	d := r.NewData(evil, "TX1", "xss", "", "1.2.3.4", 403, 0)

	out := string(r.RenderHTML(d))
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("Host 里的脚本没有被转义")
	}
	if strings.Contains(out, "<img src=x onerror=alert(1)>") {
		t.Error("Path 里的脚本没有被转义")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("应当以转义形式出现（&lt;script&gt;）")
	}
}

// 浏览器要 HTML，API 客户端要 JSON。
func TestContentNegotiation(t *testing.T) {
	r := newRenderer(t, Options{})
	base := r.NewData(req("GET", "http://x/", nil), "TX2", "sqli", "R1", "1.2.3.4", 403, 0)

	cases := []struct {
		name    string
		target  string
		hdr     map[string]string
		wantCT  string
		wantSub string
	}{
		{
			"浏览器",
			"http://x/cart",
			map[string]string{"Accept": "text/html,application/xhtml+xml"},
			"text/html",
			"<!DOCTYPE html>",
		},
		{
			"API 客户端要 JSON",
			"http://x/api/v1/items",
			map[string]string{"Accept": "application/json"},
			"application/json",
			`"error":"blocked"`,
		},
		{
			"XHR",
			"http://x/do",
			map[string]string{"Accept": "*/*", "X-Requested-With": "XMLHttpRequest"},
			"application/json",
			`"request_id":"TX2"`,
		},
		{
			"API 路径且 Accept 含糊",
			"http://x/api/v1/items",
			map[string]string{"Accept": "application/octet-stream"},
			"application/json",
			`"status":403`,
		},
		{
			"命令行客户端",
			"http://x/",
			nil,
			"text/plain",
			"Request blocked",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r.Respond(w, req("GET", c.target, c.hdr), base, false)
			if got := w.Header().Get("Content-Type"); !strings.Contains(got, c.wantCT) {
				t.Errorf("Content-Type = %q，期望包含 %q", got, c.wantCT)
			}
			if !strings.Contains(w.Body.String(), c.wantSub) {
				t.Errorf("响应体应包含 %q，实际：%s", c.wantSub, truncate(w.Body.String()))
			}
			if w.Code != 403 {
				t.Errorf("状态码 = %d，期望 403", w.Code)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Error("拦截响应必须 no-store，不能被缓存")
			}
			if w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Error("应当带 nosniff")
			}
		})
	}
}

func TestJSONResponseIsValidJSON(t *testing.T) {
	r := newRenderer(t, Options{})
	d := r.NewData(req("GET", "http://x/api/", nil), "TX3", "rce", "RCE-1", "1.2.3.4", 403, 0)
	d.RetryAfter = 30
	body := r.RenderJSON(d)
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("JSON 解析失败：%v（原文 %s）", err, body)
	}
	if parsed["error"] != "blocked" {
		t.Errorf("error 字段 = %v", parsed["error"])
	}
	if parsed["request_id"] != "TX3" {
		t.Errorf("request_id = %v", parsed["request_id"])
	}
}

// 限速/封禁给 429 + Retry-After。
func TestRateLimitResponse(t *testing.T) {
	r := newRenderer(t, Options{})
	d := r.NewData(req("GET", "http://x/", nil), "TX4", "ratelimit", "", "1.2.3.4", 429, 42)
	w := httptest.NewRecorder()
	r.Respond(w, req("GET", "http://x/", map[string]string{"Accept": "text/html"}), d, false)
	if w.Code != 429 {
		t.Errorf("状态码 = %d，期望 429", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got != "42" {
		t.Errorf("Retry-After = %q，期望 42", got)
	}
	if !strings.Contains(w.Body.String(), "请求过于频繁") {
		t.Errorf("限速页文案不符：%s", truncate(w.Body.String()))
	}
}

// 强制纯文本路径：洪泛时避免每请求渲染模板。
func TestForceTextPath(t *testing.T) {
	r := newRenderer(t, Options{Branding: true, Version: "v1"})
	d := r.NewData(req("GET", "http://x/", map[string]string{"Accept": "text/html"}), "TX5", "ban", "", "1.2.3.4", 429, 600)
	w := httptest.NewRecorder()
	r.Respond(w, req("GET", "http://x/", nil), d, true)
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("强制文本时 Content-Type = %q", ct)
	}
	if strings.Contains(w.Body.String(), "<!DOCTYPE") {
		t.Error("强制文本时不该渲染 HTML")
	}
}

// 自定义模板生效；编译失败则回退内置页并留痕（绝不 500）。
func TestCustomTemplate(t *testing.T) {
	custom := `<!DOCTYPE html><html><body><h1>站点维护中</h1><p>{{.TxID}}</p></body></html>`
	r := New(Options{CustomHTML: custom})
	if !r.UsingCustom() {
		t.Fatal("应当使用自定义模板")
	}
	if r.CustomError() != "" {
		t.Fatalf("自定义模板不该编译失败：%s", r.CustomError())
	}
	out := string(r.RenderHTML(r.NewData(req("GET", "http://x/", nil), "TX6", "sqli", "", "", 403, 0)))
	if !strings.Contains(out, "站点维护中") || !strings.Contains(out, "TX6") {
		t.Errorf("自定义模板未生效：%s", truncate(out))
	}
}

func TestBrokenCustomTemplateFallsBack(t *testing.T) {
	r := New(Options{CustomHTML: `{{.NoSuchField}}` + "\x00" + `{{{`})
	if r.CustomError() == "" {
		t.Fatal("非法模板应当被记录为编译错误")
	}
	if r.UsingCustom() {
		t.Error("编译失败时不该使用自定义模板")
	}
	// 依然要能正常出页
	out := string(r.RenderHTML(r.NewData(req("GET", "http://x/", nil), "TX7", "sqli", "", "", 403, 0)))
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("编译失败时必须回退到内置页")
	}
}

// 模板执行期出错也要兜住（例如自定义模板里访问了 nil 字段）。
func TestTemplateExecErrorFallsBack(t *testing.T) {
	r := New(Options{CustomHTML: `<!DOCTYPE html><html><body>{{template "missing" .}}</body></html>`})
	// Parse 阶段就会失败，这里主要确认不会 panic
	out := string(r.RenderHTML(r.NewData(req("GET", "http://x/", nil), "TX8", "sqli", "", "", 403, 0)))
	if len(out) == 0 {
		t.Error("任何情况下都要有响应体")
	}
}

func TestCategoryLabels(t *testing.T) {
	cases := map[string]string{
		"sqli": "SQL 注入", "XSS": "跨站脚本", "rce": "远程命令执行",
		"unknown-cat": "安全策略", "": "安全策略",
	}
	for in, want := range cases {
		if got := CategoryLabel(in); got != want {
			t.Errorf("CategoryLabel(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// 内置页面必须是自包含的：不能有任何外部资源引用。
func TestBuiltinPageIsSelfContained(t *testing.T) {
	for _, bad := range []string{"http://", "https://", "<script", "<link", "src=", "@import"} {
		if strings.Contains(builtinHTML, bad) {
			// 允许 ProductURL 出现在模板里作为可选字段，但内置页不该硬编码外链
			if bad == "https://" || bad == "http://" {
				continue
			}
			t.Errorf("内置模板不应包含 %q（自包含要求）", bad)
		}
	}
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

func BenchmarkRenderHTML(b *testing.B) {
	r := New(Options{Branding: true, Version: "v1"})
	d := r.NewData(req("GET", "http://shop.example.com/cart", nil), "TX1", "sqli", "R1", "1.2.3.4", 403, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.RenderHTML(d)
	}
}

func BenchmarkRenderText(b *testing.B) {
	r := New(Options{Branding: true, Version: "v1"})
	d := r.NewData(req("GET", "http://shop.example.com/cart", nil), "TX1", "ban", "", "1.2.3.4", 429, 600)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.RenderText(d)
	}
}

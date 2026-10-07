package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 预览票据的存储必须有界：条数上限 + TTL + 单份大小上限（无界即漏洞）。
func TestBlockPreviewStoreIsBoundedAndExpires(t *testing.T) {
	s := newBlockPreviewStore()
	tokens := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		tok, ok := s.put("<h1>预览</h1>")
		if !ok {
			t.Fatalf("第 %d 份应当能存下", i)
		}
		tokens = append(tokens, tok)
	}
	if _, ok := s.get(tokens[0]); ok {
		t.Error("超过上限后最旧的一份应被淘汰")
	}
	last := tokens[len(tokens)-1]
	if _, ok := s.get(last); !ok {
		t.Error("最新的一份应当还在")
	}

	// 过期后取不到
	s.mu.Lock()
	item := s.items[last]
	item.expires = time.Now().Add(-time.Second)
	s.items[last] = item
	s.mu.Unlock()
	if _, ok := s.get(last); ok {
		t.Error("过期的票据不该还能取到")
	}

	if _, ok := s.put(strings.Repeat("a", blockPreviewMaxBody+1)); ok {
		t.Error("超过单份上限的渲染结果不该存下（截断的预览会骗人）")
	}
	if _, ok := s.put(""); ok {
		t.Error("空内容不该存下")
	}
}

// 端到端：换票据 → 取回渲染结果，且响应自带沙箱 CSP（模板里的脚本不执行）。
func TestBlockPagePreviewTicketAndRenderAreSandboxed(t *testing.T) {
	s := newTestConsole(t)
	id, csrf, err := s.session.create("admin", "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatalf("建会话失败：%v", err)
	}
	sessionCookieFor := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
	}
	// 写操作四道全过：会话 cookie + CSRF cookie（签名过的）+ 自定义头 + CSRF 头
	writeHeaders := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: signCSRF(s.secret, csrf)})
		r.Header.Set(consoleHeader, "1")
		r.Header.Set(csrfHeader, csrf)
	}

	payload := `{"html":"<h1>PREVIEW-MARKER</h1><script>alert(1)</script>",` +
		`"method":"GET","host":"example.com","path":"/x","category":"sqli"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/block-page/preview/ticket", strings.NewReader(payload))
	writeHeaders(req)
	rec := httptest.NewRecorder()
	s.handleBlockPagePreviewTicket(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("换票据应当 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("票据响应不是合法 JSON：%v（%s）", err, rec.Body.String())
	}
	if out.Token == "" || out.ExpiresIn <= 0 {
		t.Fatalf("票据或有效期缺失：%s", rec.Body.String())
	}

	// iframe 只能发 GET（带 cookie、带不上 CSRF 头）—— 这正是拆两步的原因
	get := httptest.NewRequest(http.MethodGet, "/api/v1/block-page/preview/"+out.Token, nil)
	sessionCookieFor(get)
	grec := httptest.NewRecorder()
	s.handleBlockPagePreviewRender(grec, get)
	if grec.Code != http.StatusOK {
		t.Fatalf("取预览应当 200，实际 %d：%s", grec.Code, grec.Body.String())
	}
	if ct := grec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("预览响应的 Content-Type 应为 html，实际 %q", ct)
	}
	csp := grec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"sandbox", "default-src 'none'", "style-src 'unsafe-inline'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("预览响应缺少沙箱约束 %q：%q", want, csp)
		}
	}
	if got := grec.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Fatalf("预览响应应允许同源内嵌，实际 X-Frame-Options=%q", got)
	}
	if body := grec.Body.String(); !strings.Contains(body, "PREVIEW-MARKER") {
		t.Fatalf("预览内容不对：%s", body)
	}

	// 不存在的票据必须是 404，不能回落到任何默认页
	miss := httptest.NewRequest(http.MethodGet, "/api/v1/block-page/preview/deadbeef", nil)
	sessionCookieFor(miss)
	mrec := httptest.NewRecorder()
	s.handleBlockPagePreviewRender(mrec, miss)
	if mrec.Code != http.StatusNotFound {
		t.Fatalf("未知票据应 404，实际 %d", mrec.Code)
	}

	// 模板编译不过时换票据要整次拒绝
	bad := httptest.NewRequest(http.MethodPost, "/api/v1/block-page/preview/ticket",
		strings.NewReader(`{"html":"<h1>{{.NoSuchField}}</h1>"}`))
	writeHeaders(bad)
	brec := httptest.NewRecorder()
	s.handleBlockPagePreviewTicket(brec, bad)
	if brec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("编译不过的模板应当 422，实际 %d：%s", brec.Code, brec.Body.String())
	}
}

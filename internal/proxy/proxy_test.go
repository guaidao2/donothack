package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"donothack/internal/audit"
)

func testOptions(t *testing.T, rawURL string) Options {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("解析测试上游地址失败：%v", err)
	}
	return Options{
		Upstream:              u,
		DialTimeout:           2 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		MaxIdleConnsPerHost:   4,
	}
}

// 转发必须保真：方法、路径、查询串、请求体、上游自定义头与状态码一个都不能变。
func TestForwardsRequestFaithfully(t *testing.T) {
	type captured struct {
		method, path, rawQuery, body, xff, reqID, contentType, host string
	}
	var got captured

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = captured{
			method:      r.Method,
			path:        r.URL.Path,
			rawQuery:    r.URL.RawQuery,
			body:        string(b),
			xff:         r.Header.Get("X-Forwarded-For"),
			reqID:       r.Header.Get("X-Request-ID"),
			contentType: r.Header.Get("Content-Type"),
			host:        r.Host,
		}
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}))
	defer upstream.Close()

	p := New(testOptions(t, upstream.URL))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "http://example.com/a/b?x=1&y=%2F", strings.NewReader("hello=world"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(audit.WithRecorder(req.Context(), audit.NewRecorder()))

	p.ServeHTTP(rec, req)

	if got.method != "POST" {
		t.Errorf("方法 = %q", got.method)
	}
	if got.path != "/a/b" {
		t.Errorf("路径 = %q", got.path)
	}
	if got.rawQuery != "x=1&y=%2F" {
		t.Errorf("查询串 = %q（必须原样保留，不能重新编码）", got.rawQuery)
	}
	if got.body != "hello=world" {
		t.Errorf("请求体 = %q", got.body)
	}
	if got.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", got.contentType)
	}
	if got.xff == "" {
		t.Error("必须追加 X-Forwarded-For")
	}
	if got.reqID == "" {
		t.Error("必须把事务 ID 透给上游（X-Request-ID）")
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("状态码 = %d，期望 201", rec.Code)
	}
	if rec.Header().Get("X-Upstream") != "yes" {
		t.Error("上游响应头必须透传")
	}
	if rec.Body.String() != "created" {
		t.Errorf("响应体 = %q", rec.Body.String())
	}
}

// 默认不改写 Host（走上游主机名），开了 preserve_host 才保留原始 Host。
func TestPreserveHostOption(t *testing.T) {
	var seenHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)

	o := testOptions(t, upstream.URL)
	p := New(o)
	req := httptest.NewRequest("GET", "http://public.example.com/x", nil)
	p.ServeHTTP(httptest.NewRecorder(), req)
	if seenHost != u.Host {
		t.Errorf("默认应使用上游主机名 %q，实际 %q", u.Host, seenHost)
	}

	o.PreserveHost = true
	p2 := New(o)
	req2 := httptest.NewRequest("GET", "http://public.example.com/x", nil)
	p2.ServeHTTP(httptest.NewRecorder(), req2)
	if seenHost != "public.example.com" {
		t.Errorf("preserve_host 时应保留原始 Host，实际 %q", seenHost)
	}
}

// 客户端看到的 X-Request-ID 必须只有一个值，且是我们的 tx id。
// 上游如果回显了同名头，必须被清掉 —— 否则会变成 "ours,theirs"。
func TestResponseRequestIDIsSingleValue(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", "upstream-自带的id")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := New(testOptions(t, upstream.URL))
	rec := audit.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	req = req.WithContext(audit.WithRecorder(req.Context(), rec))

	// server 层负责在响应头写事务 ID，这里模拟同样的行为。
	rr := httptest.NewRecorder()
	rr.Header().Set("X-Request-ID", rec.TxID)
	p.ServeHTTP(rr, req)

	got := rr.Header().Values("X-Request-ID")
	if len(got) != 1 {
		t.Fatalf("X-Request-ID 应当只有一个值，实际 %d 个：%v", len(got), got)
	}
	if got[0] != rec.TxID {
		t.Errorf("X-Request-ID = %q，期望事务 ID %q", got[0], rec.TxID)
	}
}

// 上游不可达必须返回 502。**绝不静默直连** —— 那等于凭空绕过 WAF。
func TestUpstreamDownReturns502(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	upstreamURL := upstream.URL
	upstream.Close() // 立刻关掉，制造不可达

	p := New(testOptions(t, upstreamURL))
	rec := httptest.NewRecorder()
	rec2 := audit.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com/x", nil)
	req = req.WithContext(audit.WithRecorder(req.Context(), rec2))

	p.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("状态码 = %d，期望 502", rec.Code)
	}
	if rec2.Verdict != "bad_gateway" {
		t.Errorf("事务裁决应记为 bad_gateway，实际 %q", rec2.Verdict)
	}
	if rec2.Err == "" {
		t.Error("必须把上游错误记进事务，便于排查")
	}
	// 不能把上游地址泄露给客户端。
	if strings.Contains(rec.Body.String(), upstreamURL) {
		t.Errorf("响应体不得泄露上游地址：%q", rec.Body.String())
	}
}

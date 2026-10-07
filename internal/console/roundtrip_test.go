package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"donothack/internal/control"
)

// "编辑整份配置"的往返：GET 的响应原样 PUT 回去必须能过。
//
// 这条是真实 bug 的回填：GET /ratelimit 带 ban_window_s / ban_duration_s / stats，
// 而 PUT 只认 7 个字段 + 严格解码 —— 用户在编辑框里改一个数字提交，得到的是
// "请求体不是合法 JSON"，看着像格式错误。同类问题用静态门禁（scripts/api_contract.py
// 的编辑往返契约）钉住，这里再补一条运行时的。
func TestRateLimitAcceptsItsOwnGETResponse(t *testing.T) {
	// 用带限速初值的控制面构造（newTestConsole 的初值里 RPS 是 0，会被校验拒绝）
	ctl := control.New(control.Options{Initial: &control.State{
		Version:       "v1",
		DisabledRules: map[string]bool{},
		RateLimit: control.RateLimitState{
			Enabled:      true,
			RPS:          100,
			Burst:        200,
			BanAfterHits: 20,
			BanWindow:    60 * time.Second,
			BanDuration:  300 * time.Second,
			Whitelist:    []string{"127.0.0.1/32"},
		},
	}})
	s, _, err := New(Options{Config: testConfig(), Control: ctl, Version: "test"})
	if err != nil {
		t.Fatalf("构造控制台失败：%v", err)
	}
	id, csrf, _ := s.session.create("admin", "127.0.0.1", "test", time.Hour)
	auth := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: signCSRF(s.secret, csrf)})
		r.Header.Set(consoleHeader, "1")
		r.Header.Set(csrfHeader, csrf)
	}

	// 1) 读回整份配置
	get := httptest.NewRequest(http.MethodGet, "/api/v1/ratelimit", nil)
	auth(get)
	grec := httptest.NewRecorder()
	s.handleRateLimit(grec, get)
	if grec.Code != http.StatusOK {
		t.Fatalf("GET 应当 200，实际 %d", grec.Code)
	}
	body := grec.Body.Bytes()

	// 2) 原样提交回去
	put := httptest.NewRequest(http.MethodPut, "/api/v1/ratelimit", strings.NewReader(string(body)))
	auth(put)
	prec := httptest.NewRecorder()
	s.handleRateLimit(prec, put)
	if prec.Code == http.StatusBadRequest {
		t.Fatalf("GET 的响应原样提交必须被接受，却回了 400（严格解码把派生字段当非法）：%s", prec.Body.String())
	}
	if prec.Code != http.StatusOK {
		t.Fatalf("原样往返应当 200，实际 %d：%s", prec.Code, prec.Body.String())
	}
}

// 告警配置的往返：GET 里的 webhook 是**脱敏**的，原样提交不能把真地址替换成掩码。
func TestNotifyRoundTripKeepsWebhookWhenRedacted(t *testing.T) {
	s := newTestConsole(t)
	const real = "https://hooks.example.com/services/T000/B000/XXXXXXXXXXXX"
	s.o.Config.Alert.Webhook = real
	s.o.Config.Alert.Enabled = true

	id, csrf, _ := s.session.create("admin", "127.0.0.1", "test", time.Hour)
	auth := func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: signCSRF(s.secret, csrf)})
		r.Header.Set(consoleHeader, "1")
		r.Header.Set(csrfHeader, csrf)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/notify", nil)
	auth(get)
	grec := httptest.NewRecorder()
	s.handleNotify(grec, get)
	if grec.Code != http.StatusOK {
		t.Fatalf("GET 应当 200，实际 %d", grec.Code)
	}
	var view map[string]any
	if err := json.Unmarshal(grec.Body.Bytes(), &view); err != nil {
		t.Fatalf("GET 响应不是合法 JSON：%v", err)
	}
	if view["webhook"] == real {
		t.Fatal("GET 不该回显完整 webhook（那本身就是个泄漏）")
	}

	put := httptest.NewRequest(http.MethodPut, "/api/v1/notify", strings.NewReader(grec.Body.String()))
	auth(put)
	prec := httptest.NewRecorder()
	s.handleNotify(prec, put)
	if prec.Code == http.StatusBadRequest {
		t.Fatalf("GET 的响应原样提交必须被接受，却回了 400：%s", prec.Body.String())
	}
	if prec.Code != http.StatusOK {
		t.Fatalf("原样往返应当 200，实际 %d：%s", prec.Code, prec.Body.String())
	}
	if s.o.Config.Alert.Webhook != real {
		t.Fatalf("脱敏串被写进了配置！现在是：%q", s.o.Config.Alert.Webhook)
	}
}

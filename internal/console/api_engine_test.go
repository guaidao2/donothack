package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 引擎热参数端点：GET 读运行中的值；PUT 走 control.Apply（校验 → 原子替换 → 失败回滚）。
//
// 这一组测试守的是"应急切模式"这条路真的通：
// 在此之前页面上没有入口，那个"编辑整份配置"的对话框点保存必然 405 ——
// 运维在攻击已经在打的时候，改不动模式。

func engineRequest(t *testing.T, s *Server, method, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	id, csrf, err := s.session.create("admin", "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "http://127.0.0.1:18081/api/v1/engine", nil)
	} else {
		r = httptest.NewRequest(method, "http://127.0.0.1:18081/api/v1/engine", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Host = "127.0.0.1:18081"
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
	r.AddCookie(&http.Cookie{Name: csrfCookie, Value: signCSRF(s.secret, csrf)})
	r.Header.Set(consoleHeader, "1")
	r.Header.Set(csrfHeader, csrf)
	w := httptest.NewRecorder()
	s.handleEngine(w, r)
	return w, csrf
}

func TestEngineEndpointSwitchesMode(t *testing.T) {
	s := newTestConsole(t)

	// 初始：控制面里没设模式（空串），PUT 之后必须真的换掉。
	w, _ := engineRequest(t, s, http.MethodPut, `{"mode":"block","inbound_anomaly_threshold":7}`)
	if w.Code != http.StatusOK {
		t.Fatalf("切模式应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应不是 JSON：%v", err)
	}
	if got["mode"] != "block" {
		t.Errorf("响应 mode 应为 block，实际 %v", got["mode"])
	}
	if got["inbound_anomaly_threshold"] != float64(7) {
		t.Errorf("阈值应为 7，实际 %v", got["inbound_anomaly_threshold"])
	}

	// GET 必须反映**运行中**的值（来自 control.Snapshot，而不是磁盘配置）。
	w2, _ := engineRequest(t, s, http.MethodGet, "")
	if w2.Code != http.StatusOK {
		t.Fatalf("读引擎参数应 200，实际 %d", w2.Code)
	}
	var read map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &read); err != nil {
		t.Fatalf("响应不是 JSON：%v", err)
	}
	if read["mode"] != "block" {
		t.Errorf("运行中的 mode 应为 block，实际 %v", read["mode"])
	}
}

// 非法模式必须被拒且**不改动**当前状态 —— 这是"校验不过就回滚"的那条。
func TestEngineEndpointRejectsBadMode(t *testing.T) {
	s := newTestConsole(t)
	if w, _ := engineRequest(t, s, http.MethodPut, `{"mode":"block"}`); w.Code != http.StatusOK {
		t.Fatalf("先切成 block 应成功，实际 %d", w.Code)
	}
	w, _ := engineRequest(t, s, http.MethodPut, `{"mode":"panic"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("非法模式应 422，实际 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "apply_failed") {
		t.Errorf("错误码应为 apply_failed，实际 %s", w.Body.String())
	}
	snap := s.o.Control.Snapshot()
	if snap.Engine.Mode != "block" {
		t.Errorf("非法请求不应改动运行状态，实际 %q", snap.Engine.Mode)
	}
}

// 一个字段都不给：当成读操作回答，而不是"改成功"——静默成功会让人以为生效了。
func TestEngineEndpointEmptyBodyIsReadNotWrite(t *testing.T) {
	s := newTestConsole(t)
	w, _ := engineRequest(t, s, http.MethodPut, `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("空请求应 200（按读处理），实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Errorf("应返回当前参数，实际 %s", w.Body.String())
	}
}

// 真机上被指出来的 bug：在控制台切到 block 之后，"运行模式"卡显示 block，
// 而"概览"（`/status`）还写着 detect —— 因为两处各读各的来源
// （控制面 State vs 内存里的 Config 对象）。
//
// 这条测试把"只有一份真值"钉住：切完模式，所有对外读数必须一致。
func TestEngineSwitchIsReflectedInStatusAndConfig(t *testing.T) {
	s := newTestConsole(t)
	if w, _ := engineRequest(t, s, http.MethodPut,
		`{"mode":"block","inbound_anomaly_threshold":9}`); w.Code != http.StatusOK {
		t.Fatalf("切模式应 200，实际 %d：%s", w.Code, w.Body.String())
	}
	id, _, err := s.session.create("admin", "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string, fn http.HandlerFunc) string {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18081"+path, nil)
		req.Host = "127.0.0.1:18081"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
		rec := httptest.NewRecorder()
		fn(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s 应 200，实际 %d：%s", path, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	status := read("/api/v1/status", s.handleStatus)
	if !strings.Contains(status, `"mode":"block"`) {
		t.Errorf("/status 应报 block（概览读它），实际 %s", firstN(status, 160))
	}
	cfg := read("/api/v1/config", s.handleConfig)
	if !strings.Contains(cfg, `"mode":"block"`) {
		t.Errorf("/config 的 engine.mode 应为 block，实际 %s", firstN(cfg, 200))
	}
	// 运行模式卡自己读的那份也必须一致（同一个真值，三处读数相同）。
	eng, _ := engineRequest(t, s, http.MethodGet, "")
	if !strings.Contains(eng.Body.String(), `"mode":"block"`) {
		t.Errorf("/engine 应报 block，实际 %s", firstN(eng.Body.String(), 160))
	}
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
func TestEngineEndpointStillRequiresCSRF(t *testing.T) {
	s := newTestConsole(t)

	// 1) 连会话都没有：第一道就给 401（不是 403 —— 先认证后跨站）。
	r := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:18081/api/v1/engine",
		strings.NewReader(`{"mode":"block"}`))
	r.Host = "127.0.0.1:18081"
	w := httptest.NewRecorder()
	s.handleEngine(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("无会话应 401，实际 %d：%s", w.Code, w.Body.String())
	}

	// 2) 有会话但缺少自定义头
	id, csrf, err := s.session.create("admin", "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	withSession := func() *http.Request {
		req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1:18081/api/v1/engine",
			strings.NewReader(`{"mode":"block"}`))
		req.Host = "127.0.0.1:18081"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
		req.AddCookie(&http.Cookie{Name: csrfCookie, Value: signCSRF(s.secret, csrf)})
		return req
	}
	w2 := httptest.NewRecorder()
	s.handleEngine(w2, withSession())
	if w2.Code != http.StatusForbidden || !strings.Contains(w2.Body.String(), "missing_console_header") {
		t.Fatalf("缺自定义头应 403 missing_console_header，实际 %d：%s", w2.Code, w2.Body.String())
	}

	// 3) 有会话与自定义头，但没有 CSRF 头
	req := withSession()
	req.Header.Set(consoleHeader, "1")
	w3 := httptest.NewRecorder()
	s.handleEngine(w3, req)
	if w3.Code != http.StatusForbidden || !strings.Contains(w3.Body.String(), "missing_csrf") {
		t.Fatalf("缺 CSRF 应 403 missing_csrf，实际 %d：%s", w3.Code, w3.Body.String())
	}
	_ = csrf
}

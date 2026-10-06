package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"donothack/internal/audit"
	"donothack/internal/config"
	"donothack/internal/profile"
)

type testEnv struct {
	srv     *Server
	logs    *syncBuffer // 访问/审计日志
	appLogs *syncBuffer // 应用日志
}

// syncBuffer 是并发安全的日志缓冲：server 的写日志发生在请求 goroutine 里。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func newTestServer(t *testing.T, upstreamURL string, maxConns int, next http.Handler) *testEnv {
	t.Helper()

	cfg := config.Default()
	cfg.Upstream.URL = upstreamURL
	cfg.Listen.MaxConns = maxConns
	p := profile.Get(profile.Medium)
	cfg.ApplyProfile(p)
	if maxConns > 0 {
		cfg.Listen.MaxConns = maxConns
	}
	cfg.ResolvedProfile = profile.Medium
	cfg.ProfileSource = "测试"

	logs := &syncBuffer{}
	appLogs := &syncBuffer{}
	lg, err := audit.New(audit.Options{Level: "debug", Format: "json", Writer: logs, AppWriter: appLogs})
	if err != nil {
		t.Fatalf("构造日志器失败：%v", err)
	}

	if next == nil {
		next = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "proxied")
		})
	}

	srv := New(Options{
		Config:        cfg,
		Profile:       p,
		ProfileName:   profile.Medium,
		ProfileSource: "测试",
		Budget:        profile.ComputeBudget(p, 2<<30, "test"),
		Detection:     profile.Detection{NumCPU: 2, MemBytes: 2 << 30, MemSource: "test", Resolved: profile.Medium},
		MemLimit:      1 << 30,
		Logger:        lg,
		Next:          next,
		Version:       "test",
		Ruleset:       "test-ruleset",
	})
	// 这些用例直接调 Handler()，没有走 ServeListener，所以手动把 ready 置上：
	// /readyz 在监听器未起来时返回 503 是正确行为，不是这里要测的东西。
	srv.ready.Store(true)
	return &testEnv{srv: srv, logs: logs, appLogs: appLogs}
}

// 应用日志与访问日志必须落在不同的 sink：混在一起就没法"按记录类型过滤审计"。
func TestAppAndAccessLogsAreSeparated(t *testing.T) {
	env := newTestServer(t, "http://127.0.0.1:9000", 16, nil)
	env.srv.o.Logger.App().Info("测试用应用日志")
	h := env.srv.Handler()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/thing", nil))

	auditOut := env.logs.String()
	appOut := env.appLogs.String()

	if auditOut == "" {
		t.Fatal("访问日志为空")
	}
	if appOut == "" {
		t.Fatal("应用日志为空（启动日志应当出现）")
	}
	if strings.Contains(auditOut, `"msg":`) {
		t.Errorf("访问日志里混进了应用日志：%s", auditOut)
	}
	if strings.Contains(appOut, `"tx_id"`) {
		t.Errorf("应用日志里混进了访问日志：%s", appOut)
	}
}

func TestHealthzAlwaysOK(t *testing.T) {
	env := newTestServer(t, "http://127.0.0.1:9000", 16, nil)
	rec := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz 状态码 = %d，期望 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("/healthz 响应体异常：%q", rec.Body.String())
	}
}

func TestReadyzExposesProfileAndBudget(t *testing.T) {
	env := newTestServer(t, "http://127.0.0.1:9000", 16, nil)
	rec := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("/readyz 状态码 = %d，期望 200；响应体：%s", rec.Code, rec.Body.String())
	}
	var info ReadyInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("解析 /readyz 响应失败：%v", err)
	}
	if info.Profile != string(profile.Medium) {
		t.Errorf("profile = %q，期望 medium", info.Profile)
	}
	if info.BudgetMiB <= 0 {
		t.Errorf("预算 = %v MiB，应当为正", info.BudgetMiB)
	}
	if !info.UpstreamOK {
		t.Errorf("IP 字面量上游应当被判为可达：%s", info.UpstreamDetail)
	}
	// /readyz 必须原样报出加载了哪个规则集 —— 排查"规则到底生效没有"全靠它。
	if info.Ruleset != "test-ruleset" {
		t.Errorf("规则集摘要应原样暴露，实际 %q", info.Ruleset)
	}
}

// 没加载规则集时必须如实为空，不能假装有防护。
func TestReadyzReportsEmptyRuleset(t *testing.T) {
	env := newTestServer(t, "http://127.0.0.1:9000", 16, nil)
	env.srv.o.Ruleset = ""
	rec := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))

	var info ReadyInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("解析 /readyz 响应失败：%v", err)
	}
	if info.Ruleset != "" {
		t.Errorf("未加载规则集时应为空，实际 %q", info.Ruleset)
	}
}

// 上游 DNS 解析不了时 readiness 必须变 503，否则流量会被送进一个注定失败的口子。
func TestReadyzUnavailableWhenUpstreamUnresolvable(t *testing.T) {
	env := newTestServer(t, "http://nonexistent-upstream.invalid:9000", 16, nil)
	rec := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz 状态码 = %d，期望 503", rec.Code)
	}
}

// 并发上限必须真的生效：超限返回 503，而不是把内存吃穿。
func TestConnLimitReturns503(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	})

	env := newTestServer(t, "http://127.0.0.1:9000", 1, next)
	h := env.srv.Handler()

	first := httptest.NewRecorder()
	go h.ServeHTTP(first, httptest.NewRequest("GET", "/slow", nil))

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("第一个请求未能进入处理器")
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest("GET", "/second", nil))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("超限请求状态码 = %d，期望 503", second.Code)
	}
	if got := second.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q，期望 1", got)
	}

	close(release)
	time.Sleep(50 * time.Millisecond)
	if first.Code != http.StatusOK {
		t.Errorf("第一个请求状态码 = %d，期望 200", first.Code)
	}
	if !strings.Contains(env.logs.String(), "rejected_busy") {
		t.Error("超限事件必须出现在访问日志里")
	}
}

func TestAccessLogExcludesProbes(t *testing.T) {
	env := newTestServer(t, "http://127.0.0.1:9000", 16, nil)
	h := env.srv.Handler()

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/healthz", nil))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/readyz", nil))
	if got := env.logs.String(); strings.Contains(got, "healthz") || strings.Contains(got, "readyz") {
		t.Errorf("健康探针不应写访问日志，实际日志：%s", got)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/thing?x=1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("业务请求状态码 = %d", rec.Code)
	}

	var got audit.AccessRecord
	for _, line := range strings.Split(strings.TrimSpace(env.logs.String()), "\n") {
		if line == "" {
			continue
		}
		var candidate audit.AccessRecord
		if err := json.Unmarshal([]byte(line), &candidate); err != nil {
			t.Fatalf("访问日志不是合法 JSON：%s", line)
		}
		if candidate.URI != "" {
			got = candidate
		}
	}
	if got.URI != "/api/thing?x=1" {
		t.Errorf("访问日志 URI = %q", got.URI)
	}
	if got.TxID == "" {
		t.Error("访问日志必须带 tx_id")
	}
	if got.Profile != string(profile.Medium) {
		t.Errorf("访问日志 profile = %q", got.Profile)
	}
}

// 优雅停机必须 drain 在途请求：这是 P0 的验收项之一。
func TestGracefulShutdownDrainsInflight(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%v", err)
	}
	addr := ln.Addr().String()

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "done")
	})

	env := newTestServer(t, "http://127.0.0.1:9000", 16, next)

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- env.srv.ServeListener(ctx, ln) }()

	type result struct {
		status int
		body   string
		err    error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/inflight")
		if err != nil {
			resCh <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		resCh <- result{status: resp.StatusCode, body: string(b)}
	}()

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("请求未能进入处理器")
	}

	// 触发停机；此时请求还在处理中，必须被 drain 而不是被砍掉。
	cancel()
	time.Sleep(100 * time.Millisecond)
	close(release)

	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("在途请求被中断：%v", r.err)
		}
		if r.status != http.StatusOK || r.body != "done" {
			t.Fatalf("在途请求结果异常：status=%d body=%q", r.status, r.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("在途请求超时未完成")
	}

	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("优雅停机返回错误：%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeListener 未在停机后返回")
	}

	if env.srv.Ready() {
		t.Error("停机后 ready 必须为 false")
	}
}

package pipeline

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"donothack/internal/blockpage"
	"donothack/internal/degrade"
	"donothack/internal/engine"
	"donothack/internal/parser"
	"donothack/internal/ratelimit"
	"donothack/internal/rules"
	"donothack/internal/tx"
)

// countingNext 记录被转发过来的请求数。
type countingNext struct{ n atomic.Uint64 }

func (c *countingNext) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.n.Add(1)
	w.WriteHeader(200)
	_, _ = w.Write([]byte("upstream"))
}

func loadTestRules(t *testing.T, yaml string) *rules.RuleSet {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("建目录失败：%v", err)
	}
	p := filepath.Join(dir, "one.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatalf("写规则失败：%v", err)
	}
	rs, err := rules.LoadFiles(rules.DefaultOptions(), []string{p})
	if err != nil {
		t.Fatalf("加载规则失败：%v", err)
	}
	return rs
}

const blockRule = `
version: 1
meta:
  name: p3-test
rules:
  - id: TEST-BLOCK
    phase: 2
    severity: critical
    category: sqli
    message: "测试用拦截规则"
    targets:
      - collection: ARGS
    transforms: [lowercase]
    operator:
      name: contains
      params: {value: "blockme"}
    action:
      type: block
    test:
      positive: ["please blockme now"]
      negative: ["normal text", "another normal one"]
`

func newEngine(t *testing.T, mode string, rs *rules.RuleSet) *engine.Engine {
	t.Helper()
	return engine.New(engine.Options{
		RuleSet:          rs,
		Mode:             mode,
		InboundThreshold: 5,
		Limits:           parser.DefaultLimits(),
	})
}

func TestPipelineForwardsWhenNoRules(t *testing.T) {
	next := &countingNext{}
	p := New(Options{Engine: newEngine(t, "detect", nil), Next: next})

	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://x/", nil))
	if next.n.Load() != 1 {
		t.Errorf("没有规则时应当转发，实际转发 %d 次", next.n.Load())
	}
	if w.Code != 200 {
		t.Errorf("状态码 = %d", w.Code)
	}
}

// block 模式下规则显式 block 动作 → 拦截页（浏览器形态）。
func TestPipelineBlocksWithPage(t *testing.T) {
	rs := loadTestRules(t, blockRule)
	next := &countingNext{}
	p := New(Options{
		Engine:    newEngine(t, "block", rs),
		Next:      next,
		BlockPage: blockpage.New(blockpage.Options{Branding: true, Version: "test"}),
	})

	req := httptest.NewRequest("GET", "http://shop.example.com/?q=please+blockme+now", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("状态码 = %d，期望 403", w.Code)
	}
	if next.n.Load() != 0 {
		t.Error("被拦截的请求不该转发到上游")
	}
	body := w.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("浏览器应当拿到 HTML 拦截页：%s", truncate(body))
	}
	if !strings.Contains(body, "SQL 注入") {
		t.Errorf("页面应显示命中的类目")
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
}

// detect 模式：规则写了 block 动作也只记录 —— 上线节奏由部署方控制。
func TestDetectModeNeverBlocks(t *testing.T) {
	rs := loadTestRules(t, blockRule)
	next := &countingNext{}
	p := New(Options{Engine: newEngine(t, "detect", rs), Next: next})

	req := httptest.NewRequest("GET", "http://x/?q=please+blockme+now", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code == 403 {
		t.Error("detect 模式下不该拦截（哪怕规则写了 block 动作）")
	}
	if next.n.Load() != 1 {
		t.Errorf("detect 模式应当转发，实际转发 %d 次", next.n.Load())
	}
}

// block 模式下降级到 L2 → 503，绝不放行未经检测的流量。
func TestDegradeRejectsInBlockMode(t *testing.T) {
	next := &countingNext{}
	dg := degrade.New(degrade.Options{Enabled: true, Mode: "block"})
	dg.SetLevel(degrade.L2)

	p := New(Options{Engine: newEngine(t, "block", nil), Next: next, Degrader: dg})
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://x/", nil))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("状态码 = %d，期望 503", w.Code)
	}
	if next.n.Load() != 0 {
		t.Error("降级拒绝时不该转发")
	}
	if p.Stats().Rejected503 != 1 {
		t.Errorf("应当统计降级拒绝，实际 %+v", p.Stats())
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("503 应当带 Retry-After，让客户端知道可以重试")
	}
}

// detect 模式下 L2 仍可服务（本来就只记录），只有 L4 才旁路。
func TestDegradeAllowsInDetectMode(t *testing.T) {
	next := &countingNext{}
	dg := degrade.New(degrade.Options{Enabled: true, Mode: "detect"})
	dg.SetLevel(degrade.L2)
	p := New(Options{Engine: newEngine(t, "detect", nil), Next: next, Degrader: dg})

	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://x/", nil))
	if w.Code != 200 || next.n.Load() != 1 {
		t.Errorf("detect 模式 L2 应当继续服务：code=%d forwarded=%d", w.Code, next.n.Load())
	}
}

// 限速触发 → 429 + Retry-After，且走纯文本（洪泛路径不做模板渲染）。
func TestRateLimitedResponseIsText(t *testing.T) {
	l, err := ratelimit.New(ratelimit.Options{RPS: 1, Burst: 1})
	if err != nil {
		t.Fatalf("构造限速器失败：%v", err)
	}
	next := &countingNext{}
	p := New(Options{
		Engine:    newEngine(t, "block", nil),
		Next:      next,
		Limiter:   l,
		BlockPage: blockpage.New(blockpage.Options{Branding: true, Version: "test"}),
	})

	// 第一个放行，第二个被限
	p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://x/", nil))
	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://x/", nil)
	req.Header.Set("Accept", "text/html") // 即使浏览器也要走文本
	p.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("状态码 = %d，期望 429", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("限速响应应当是纯文本，实际 %q", ct)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("限速响应必须带 Retry-After")
	}
	if strings.Contains(w.Body.String(), "<!DOCTYPE") {
		t.Error("限速是洪泛路径，不该渲染 HTML 模板")
	}
	if p.Stats().RateLimited == 0 {
		t.Error("应当统计限速次数")
	}
}

// 真实 IP 解析必须传进事务（限速与封禁都靠它，取错等于形同虚设）。
func TestClientIPResolvedIntoTransaction(t *testing.T) {
	next := &countingNext{}
	rs := loadTestRules(t, `
version: 1
meta:
  name: ip-test
rules:
  - id: TEST-IP
    phase: 1
    severity: low
    category: scanner
    message: "记录来源"
    targets:
      - collection: REMOTE_ADDR
    operator:
      name: contains
      params: {value: "203.0.113"}
    action:
      type: log
    test:
      positive: ["203.0.113.7"]
      negative: ["10.0.0.1", "192.168.1.1"]
`)
	eng := newEngine(t, "detect", rs)
	p := New(Options{Engine: eng, Next: next})

	req := httptest.NewRequest("GET", "http://x/", nil)
	req.RemoteAddr = "10.0.0.6:1234"
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)
	// REMOTE_ADDR 用的是客户端 IP；没有可信代理配置时就是对端地址
	if next.n.Load() != 1 {
		t.Error("应当转发")
	}
}

func TestTarpitHasUpperBound(t *testing.T) {
	p := New(Options{MaxTarpit: 10 * time.Millisecond})
	start := time.Now()
	p.tarpit(engine.Decision{Verdict: tx.VerdictTarpit})
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("tarpit 必须有上限，实际耗时 %v", d)
	}
}

func truncate(s string) string {
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// drop 动作：直接断连，不回任何响应。
func TestDropClosesConnection(t *testing.T) {
	rs := loadTestRules(t, `
version: 1
meta:
  name: drop-test
rules:
  - id: TEST-DROP
    phase: 2
    severity: critical
    category: rce
    message: "测试断连动作"
    targets:
      - collection: ARGS
    transforms: [lowercase]
    operator:
      name: contains
      params: {value: "dropme"}
    action:
      type: drop
    test:
      positive: ["x dropme y"]
      negative: ["normal", "another normal"]
`)
	next := &countingNext{}
	p := New(Options{Engine: newEngine(t, "block", rs), Next: next})

	// httptest.ResponseRecorder 不实现 Hijacker → 应退化为拦截页（不能放行）
	w := httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest("GET", "http://x/?q=please+dropme+now", nil))
	if next.n.Load() != 0 {
		t.Error("drop 动作绝不该转发到上游")
	}
	if w.Code != 403 {
		t.Errorf("不支持 Hijack 时应当退化为拦截页，状态码 = %d", w.Code)
	}
	if p.Stats().Blocked == 0 {
		t.Error("drop 也应计入拦截统计")
	}
}

package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// collector 是一个假的 webhook 接收端。
type collector struct {
	mu     sync.Mutex
	events []Event
	fail   atomic.Bool
	delay  time.Duration
}

func (c *collector) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.fail.Load() {
			w.WriteHeader(500)
			return
		}
		if c.delay > 0 {
			time.Sleep(c.delay)
		}
		var e Event
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			w.WriteHeader(400)
			return
		}
		c.mu.Lock()
		c.events = append(c.events, e)
		c.mu.Unlock()
		w.WriteHeader(204)
	})
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func (c *collector) last() (Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.events) == 0 {
		return Event{}, false
	}
	return c.events[len(c.events)-1], true
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}

// 说明：这些用例的接收端是 httptest.NewServer（监听 127.0.0.1），
// 而出站策略默认禁止私有/回环地址 —— 所以必须显式 AllowPrivateHosts: true。
// 这不是"为了让测试过而放水"：出站策略本身有专门的用例（egress_test.go）盯着，
// 这里测的是投递机制（冷却、队列、失败计数）。
func TestNotifierPostsEvent(t *testing.T) {
	c := &collector{}
	srv := httptest.NewServer(c.handler())
	defer srv.Close()

	n := New(Options{Enabled: true, AllowPrivateHosts: true, Webhook: srv.URL, Cooldown: time.Millisecond, Instance: "test-1"})
	defer n.Close()

	n.Notify(Event{Kind: "block", Severity: "high", Category: "sqli", RuleID: "SQLI-4001",
		Target: "ARGS:id", Method: "GET", Path: "/x", ClientIP: "1.2.3.4", TxID: "tx1"})

	waitFor(t, func() bool { return c.count() == 1 })
	e, _ := c.last()
	if e.Category != "sqli" || e.TxID != "tx1" || e.Instance != "test-1" {
		t.Errorf("告警内容不符：%+v", e)
	}
	if e.At.IsZero() {
		t.Error("应当自动填时间")
	}
	if n.Stats().Sent != 1 {
		t.Errorf("应当统计发送成功，实际 %+v", n.Stats())
	}
}

// 冷却：同一类告警在冷却期内只发一条，但要带上被合并的次数。
func TestCooldownSuppressesAndCounts(t *testing.T) {
	c := &collector{}
	srv := httptest.NewServer(c.handler())
	defer srv.Close()

	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	n := New(Options{Enabled: true, AllowPrivateHosts: true, Webhook: srv.URL, Cooldown: time.Minute, Now: clk.Now})
	defer n.Close()

	for i := 0; i < 5; i++ {
		clk.Advance(time.Second)
		n.Notify(Event{Kind: "block", Category: "sqli", RuleID: "SQLI-1", Severity: "high"})
	}
	waitFor(t, func() bool { return c.count() >= 1 })
	time.Sleep(100 * time.Millisecond)

	if got := c.count(); got != 1 {
		t.Errorf("冷却期内应当只发一条，实际 %d 条", got)
	}
	if n.Stats().Suppressed != 4 {
		t.Errorf("应当统计 4 次抑制，实际 %d", n.Stats().Suppressed)
	}

	// 冷却过后再发：带上累计次数
	clk.Advance(2 * time.Minute)
	n.Notify(Event{Kind: "block", Category: "sqli", RuleID: "SQLI-1", Severity: "high"})
	waitFor(t, func() bool { return c.count() == 2 })
	e, _ := c.last()
	if e.Count != 5 {
		t.Errorf("第二次发送应带累计次数 5，实际 %d", e.Count)
	}
}

// 队列满必须**丢事件**而不是阻塞调用方。
func TestQueueFullDropsInsteadOfBlocking(t *testing.T) {
	c := &collector{delay: 200 * time.Millisecond}
	srv := httptest.NewServer(c.handler())
	defer srv.Close()

	// 冷却设为 0 让每条都进队列；队列容量 2
	n := New(Options{Enabled: true, AllowPrivateHosts: true, Webhook: srv.URL, QueueCap: 2, Cooldown: -1 /* 关闭冷却：本测试要的是"队列满"而不是"被冷却抑制" */})
	defer n.Close()

	start := time.Now()
	for i := 0; i < 100; i++ {
		n.Notify(Event{Kind: "block", Category: "xss", RuleID: "XSS-1", Severity: "high"})
	}
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Errorf("Notify 不该阻塞，100 次调用花了 %v", elapsed)
	}
	if n.Stats().Dropped == 0 {
		t.Error("队列满时应当统计丢弃")
	}
}

// webhook 挂了要有统计，且不影响后续发送。
func TestFailureIsCounted(t *testing.T) {
	c := &collector{}
	c.fail.Store(true)
	srv := httptest.NewServer(c.handler())
	defer srv.Close()

	n := New(Options{Enabled: true, AllowPrivateHosts: true, Webhook: srv.URL, Cooldown: time.Nanosecond})
	defer n.Close()
	n.Notify(Event{Kind: "block", Category: "rce", Severity: "critical"})
	waitFor(t, func() bool { return n.Stats().Failed == 1 })
	if n.Stats().LastError == "" {
		t.Error("失败原因应当被记下来")
	}

	// 恢复后仍能正常发
	c.fail.Store(false)
	n.Notify(Event{Kind: "block", Category: "lfi", Severity: "high"})
	waitFor(t, func() bool { return n.Stats().Sent == 1 })
}

func TestSeverityThreshold(t *testing.T) {
	c := &collector{}
	srv := httptest.NewServer(c.handler())
	defer srv.Close()

	n := New(Options{Enabled: true, AllowPrivateHosts: true, Webhook: srv.URL, MinSeverity: "high", Cooldown: time.Nanosecond})
	defer n.Close()
	n.Notify(Event{Kind: "block", Category: "low", Severity: "low"})
	n.Notify(Event{Kind: "block", Category: "med", Severity: "medium"})
	time.Sleep(150 * time.Millisecond)
	if c.count() != 0 {
		t.Errorf("低于门槛的告警不该发送，实际 %d 条", c.count())
	}
	n.Notify(Event{Kind: "block", Category: "crit", Severity: "critical"})
	waitFor(t, func() bool { return c.count() == 1 })
}

func TestDisabledIsNoop(t *testing.T) {
	n := New(Options{Enabled: false, Webhook: ""})
	defer n.Close()
	if n.Enabled() {
		t.Error("未配置时不该启用")
	}
	// 不该 panic，也不该有任何统计
	n.Notify(Event{Kind: "block", Severity: "critical"})
	if st := n.Stats(); st.Queued != 0 || st.Sent != 0 {
		t.Errorf("未启用时不该有任何动作：%+v", st)
	}
	if err := n.Send(context.Background(), Event{Kind: "test"}); err == nil {
		t.Error("未启用时 Send 应当返回错误")
	}
}

// 告警内容**不含 payload 原文** —— 告警常被转到 IM/邮件/工单，
// 那些地方的访问控制通常比 WAF 弱。
func TestEventHasNoPayloadField(t *testing.T) {
	raw, err := json.Marshal(Event{Kind: "block", Detail: "sqli fingerprint: union select"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"payload", "payload_before", "payload_after", "body", "raw"} {
		if _, ok := m[forbidden]; ok {
			t.Errorf("告警体不该有 %q 字段", forbidden)
		}
	}
}

func TestSendSyncForTestEndpoint(t *testing.T) {
	c := &collector{}
	srv := httptest.NewServer(c.handler())
	defer srv.Close()
	n := New(Options{Enabled: true, AllowPrivateHosts: true, Webhook: srv.URL})
	defer n.Close()
	if err := n.Send(context.Background(), Event{Kind: "test"}); err != nil {
		t.Fatalf("同步发送失败：%v", err)
	}
	if c.count() != 1 {
		t.Error("同步发送应当写到接收端")
	}
}

func BenchmarkNotify(b *testing.B) {
	c := &collector{}
	srv := httptest.NewServer(c.handler())
	defer srv.Close()
	n := New(Options{Enabled: true, AllowPrivateHosts: true, Webhook: srv.URL, QueueCap: 4096, Cooldown: time.Minute})
	defer n.Close()
	e := Event{Kind: "block", Severity: "high", Category: "sqli", RuleID: "SQLI-1"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Notify(e)
	}
}

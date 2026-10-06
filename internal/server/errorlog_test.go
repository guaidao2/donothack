package server

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// recordingHandler 收下所有被放行的日志，用于断言"哪几行真的写出来了"。
type recordingHandler struct {
	mu      sync.Mutex
	records []string
	attrs   []map[string]any
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Message)
	m := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.Any()
		return true
	})
	h.attrs = append(h.attrs, m)
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func (h *recordingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.records)
}

// TestHandshakeErrorsAreFoldedPerSource 守"同一个来源的同类握手失败只写一行"。
//
// 这一幕来自真实日志：自签证书没被信任时，浏览器一次刷新（前端 20 多个文件）
// 会产生十几二十条一模一样的 `TLS handshake error ... unknown certificate`，
// 把真正有用的记录淹掉。
func TestHandshakeErrorsAreFoldedPerSource(t *testing.T) {
	rec := &recordingHandler{}
	h := newDedupHandler(rec)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	h.window = 30 * time.Second

	line := func(port int) string {
		return "http: TLS handshake error from 192.168.44.1:" + itoa(port) + ": remote error: tls: unknown certificate"
	}

	// 同一来源 + 同类错误，紧接着 20 条 —— 只应写出 1 条。
	for i := 0; i < 20; i++ {
		if err := h.Handle(context.Background(), slog.NewRecord(now, slog.LevelWarn, line(50000+i), 0)); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	}
	if got := rec.count(); got != 1 {
		t.Fatalf("同源同类 20 条应只写 1 条，实际 %d 条", got)
	}

	// 换一个来源：不同来源不该互相折叠。
	if err := h.Handle(context.Background(), slog.NewRecord(now, slog.LevelWarn,
		"http: TLS handshake error from 10.0.0.9:40000: remote error: tls: unknown certificate", 0)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := rec.count(); got != 2 {
		t.Fatalf("换来源应立刻写一条，实际共 %d 条", got)
	}

	// 不同类别（明文访问 TLS 端口）：也不该被折叠进来。
	if err := h.Handle(context.Background(), slog.NewRecord(now, slog.LevelWarn,
		"http: TLS handshake error from 192.168.44.1:41000: client sent an HTTP request to an HTTPS server", 0)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := rec.count(); got != 3 {
		t.Fatalf("不同错误文本应立刻写一条，实际共 %d 条", got)
	}

	// 窗口过去后：写出新的一行，并带上被折叠的数量。
	now = now.Add(31 * time.Second)
	if err := h.Handle(context.Background(), slog.NewRecord(now, slog.LevelWarn, line(60000), 0)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got := rec.count(); got != 4 {
		t.Fatalf("窗口过后应写一条，实际共 %d 条", got)
	}
	last := rec.attrs[len(rec.attrs)-1]
	if got, ok := last["折叠"]; !ok || got != int64(19) {
		t.Fatalf("窗口过后那行应带折叠计数 19，实际 %v", last)
	}
}

// TestDedupKeyIgnoresPort 守"端口不参与同类判断"，否则永远折叠不了。
func TestDedupKeyIgnoresPort(t *testing.T) {
	a := dedupKey("http: TLS handshake error from 1.2.3.4:1000: remote error: tls: unknown certificate")
	b := dedupKey("http: TLS handshake error from 1.2.3.4:60000: remote error: tls: unknown certificate")
	if a != b {
		t.Fatalf("同源同类、只有端口不同，键应相同：\n  %s\n  %s", a, b)
	}
	c := dedupKey("http: TLS handshake error from 1.2.3.5:1000: remote error: tls: unknown certificate")
	if a == c {
		t.Fatal("不同来源的键不该相同")
	}
}

// TestDedupTableIsBounded 守记忆表有硬顶：来源数量不可控（被扫时可能很多）。
func TestDedupTableIsBounded(t *testing.T) {
	rec := &recordingHandler{}
	h := newDedupHandler(rec)
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	h.now = func() time.Time { return now }
	h.window = time.Second

	for i := 0; i < errLogMaxKeys*2; i++ {
		msg := "http: TLS handshake error from 10.0." + itoa(i/256) + "." + itoa(i%256) + ":1234: boom"
		if err := h.Handle(context.Background(), slog.NewRecord(now, slog.LevelWarn, msg, 0)); err != nil {
			t.Fatalf("Handle: %v", err)
		}
	}
	h.st.mu.Lock()
	n := len(h.st.entries)
	h.st.mu.Unlock()
	if n > errLogMaxKeys {
		t.Fatalf("记忆表应被硬顶在 %d 以内，实际 %d", errLogMaxKeys, n)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

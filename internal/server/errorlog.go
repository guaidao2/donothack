// 本文件把 http.Server 的错误日志按来源折叠。
//
// 起因：Go 的 http.Server 会对**每一次**失败握手写一行日志
// （`http: TLS handshake error from 192.168.44.1:57650: remote error: tls: unknown certificate`），
// 而控制台前端是原生 ES module，一个页面要加载 20 多个文件；自签证书没被信任时，
// 刷新一次页面就是十几二十条一模一样的记录，把真正有用的日志淹掉。
//
// 做法：同一个"来源 + 同类错误"在窗口内只写第一行，其余折叠成计数；窗口过去后的
// 第一行会带上"折叠了多少条"。数量这个事实没有丢，只是不再刷屏。
//
// 为什么只做最保守的归一化：这里处理的是 net/http 的内部日志，格式不是我们的契约，
// 所以不解析语义，只抹掉每次都会变的端口号，靠"归一化后整行相等"判同类。

package server

import (
	"context"
	"log"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"donothack/internal/audit"
)

const (
	// 折叠窗口：同一来源同类错误在这么久之内只写一行。
	errLogWindow = 30 * time.Second
	// 记忆项上限：来源 IP 数量不可控（被扫时可能很多），必须有硬顶。
	errLogMaxKeys = 1024
)

// 从 `... from 1.2.3.4:5678: ...` 里取出源地址（IPv4 或 IPv6）。
var errLogFromRe = regexp.MustCompile(` from (\[[0-9a-fA-F:]+\]|[0-9.]+):[0-9]+`)

// 把端口号抹掉：同一来源每次连接的端口都不同，不抹就没法折叠。
var errLogPortRe = regexp.MustCompile(`:[0-9]{2,5}\b`)

type errLogEntry struct {
	last       time.Time
	suppressed int
}

// errLogState 是所有派生 handler 共享的状态。**必须是指针**：
// slog.Handler 会被 WithAttrs/WithGroup 复制，互斥锁跟着结构体复制就失去意义了。
type errLogState struct {
	mu      sync.Mutex
	entries map[string]*errLogEntry
}

// newErrorLogger 组装 http.Server 的 ErrorLog：包装层做折叠，底层仍走应用的结构化日志。
func newErrorLogger(lg *audit.Logger) *log.Logger {
	return slog.NewLogLogger(newDedupHandler(lg.App().Handler()), slog.LevelWarn)
}

// dedupHandler 是 slog.Handler 的包装，只用于 http.Server 的 ErrorLog，
// 不碰应用自己的结构化日志。
type dedupHandler struct {
	inner  slog.Handler
	window time.Duration
	now    func() time.Time
	st     *errLogState
}

func newDedupHandler(inner slog.Handler) *dedupHandler {
	return &dedupHandler{
		inner:  inner,
		window: errLogWindow,
		now:    time.Now,
		st:     &errLogState{entries: make(map[string]*errLogEntry, 32)},
	}
}

func (h *dedupHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *dedupHandler) Handle(ctx context.Context, r slog.Record) error {
	key := dedupKey(r.Message)
	now := h.now()

	h.st.mu.Lock()
	e, seen := h.st.entries[key]
	if seen && now.Sub(e.last) < h.window {
		e.suppressed++
		h.st.mu.Unlock()
		return nil // 折叠：这一行不写
	}
	suppressed := 0
	if seen {
		suppressed = e.suppressed
	} else {
		if len(h.st.entries) >= errLogMaxKeys {
			h.evictLocked(now)
		}
		e = &errLogEntry{}
		h.st.entries[key] = e
	}
	e.last = now
	e.suppressed = 0
	h.st.mu.Unlock()

	r2 := r.Clone()
	if suppressed > 0 {
		r2.AddAttrs(slog.Int("折叠", suppressed), slog.String("窗口", h.window.String()))
	}
	return h.inner.Handle(ctx, r2)
}

func (h *dedupHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &dedupHandler{inner: h.inner.WithAttrs(attrs), window: h.window, now: h.now, st: h.st}
}

func (h *dedupHandler) WithGroup(name string) slog.Handler {
	return &dedupHandler{inner: h.inner.WithGroup(name), window: h.window, now: h.now, st: h.st}
}

// evictLocked 清掉过期项；仍然超上限就整体清空 ——
// 宁可多写几行日志，也不能让记忆表无界增长。
func (h *dedupHandler) evictLocked(now time.Time) {
	for k, e := range h.st.entries {
		if now.Sub(e.last) >= h.window {
			delete(h.st.entries, k)
		}
	}
	if len(h.st.entries) >= errLogMaxKeys {
		h.st.entries = make(map[string]*errLogEntry, 32)
	}
}

// dedupKey 归一化成"同类"的键：保留源地址（不同来源不互相折叠），抹掉端口。
func dedupKey(msg string) string {
	normalized := errLogPortRe.ReplaceAllString(msg, "")
	if m := errLogFromRe.FindStringSubmatch(msg); m != nil {
		return m[1] + "|" + normalized
	}
	return normalized
}

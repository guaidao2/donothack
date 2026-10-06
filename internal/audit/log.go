// Package audit 负责结构化日志：应用日志走 slog，访问日志走固定字段的 JSON Lines。
//
// P0 范围：同步写、stdout 或文件追加。以下能力属于 P4，届时在此包内扩展：
//   - 有界异步队列（队列满则丢弃并计数，绝不阻塞请求）
//   - 按大小与时间轮转、max_backups
//   - 命中事件 ring buffer 与分钟级聚合桶
//   - 审计字段的完整版本（events[]、ruleset_version、score）
package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Options 是日志器的构造参数。
//
// 应用日志与访问/审计日志**默认分开**：前者走 stderr，后者走 stdout 或文件。
// 混在一个文件里会让"按字段过滤审计记录"变得别扭，也让日志采集端要额外判断记录类型。
type Options struct {
	Level  string // debug | info | warn | error
	Format string // json | text

	// 访问 / 审计日志的去向
	Output string // stdout | file
	File   string

	// 应用日志的去向
	AppOutput string // stderr | stdout | file（空 = stderr）
	AppFile   string

	// Writer / AppWriter 覆盖对应去向，仅供测试与嵌入场景使用。
	Writer    io.Writer
	AppWriter io.Writer
}

// Logger 同时提供应用日志与访问日志。
//
// 应用日志（slog）与访问日志（JSON Lines）写的是同一个 writer，
// 因此两者必须共用同一把锁 —— 否则两行日志会交错，落盘内容不可解析。
type Logger struct {
	app *slog.Logger

	// mu 保护底层 writer。它只由 lockedWriter 获取：
	// 谁写谁加锁，调用方不要重复加锁（会自锁）。
	mu     sync.Mutex
	enc    *json.Encoder
	closer io.Closer
}

// lockedWriter 把 writer 的每次 Write 串行化。
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// New 构造日志器。
func New(o Options) (*Logger, error) {
	level, err := parseLevel(o.Level)
	if err != nil {
		return nil, err
	}

	var appW io.Writer = os.Stderr
	var appCloser io.Closer
	switch {
	case o.AppWriter != nil:
		appW = o.AppWriter
	default:
		w, c, err := openSink(o.AppOutput, o.AppFile, os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("应用日志：%w", err)
		}
		appW, appCloser = w, c
	}

	auditW, auditCloser, err := openSink(o.Output, o.File, os.Stdout)
	if err != nil {
		return nil, fmt.Errorf("访问日志：%w", err)
	}
	if o.Writer != nil {
		auditW, auditCloser = o.Writer, nil
	}

	lg := &Logger{closer: closerOf(appCloser, auditCloser)}
	// 两个 sink 共用一把锁：即使它们指向同一个文件，也不会出现交错的行。
	lwApp := lockedWriter{mu: &lg.mu, w: appW}
	lwAudit := lockedWriter{mu: &lg.mu, w: auditW}

	var handler slog.Handler
	hopts := &slog.HandlerOptions{Level: level}
	if o.Format == "text" {
		handler = slog.NewTextHandler(lwApp, hopts)
	} else {
		handler = slog.NewJSONHandler(lwApp, hopts)
	}
	lg.app = slog.New(handler)
	lg.enc = json.NewEncoder(lwAudit)

	return lg, nil
}

// openSink 解析 "stderr | stdout | file" 三种去向。
func openSink(output, file string, fallback io.Writer) (io.Writer, io.Closer, error) {
	switch output {
	case "", "default":
		if fallback == os.Stderr {
			return os.Stderr, nil, nil
		}
		return fallback, nil, nil
	case "stderr":
		return os.Stderr, nil, nil
	case "stdout":
		return os.Stdout, nil, nil
	case "file":
		if strings.TrimSpace(file) == "" {
			return nil, nil, fmt.Errorf("output=file 时文件路径必填")
		}
		if dir := filepath.Dir(file); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, nil, fmt.Errorf("创建日志目录 %s 失败：%w", dir, err)
			}
		}
		f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("打开日志文件 %s 失败：%w", file, err)
		}
		return f, f, nil
	default:
		return nil, nil, fmt.Errorf("未知输出目标 %q（可选 stderr | stdout | file）", output)
	}
}

type multiCloser []io.Closer

func (m multiCloser) Close() error {
	var first error
	for _, c := range m {
		if c == nil {
			continue
		}
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func closerOf(cs ...io.Closer) io.Closer {
	kept := make(multiCloser, 0, len(cs))
	for _, c := range cs {
		if c != nil {
			kept = append(kept, c)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("未知日志级别 %q", s)
	}
}

// App 返回应用日志器。
func (l *Logger) App() *slog.Logger { return l.app }

// Close 关闭底层文件。
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// AccessRecord 是访问日志的一行。字段名稳定，便于日志系统解析。
//
// 注意：这里**不记录 payload**。payload 落盘由 log.capture_payload 控制，
// 且只进命中事件（P4），不进访问日志。
type AccessRecord struct {
	Ts         string  `json:"ts"`
	TxID       string  `json:"tx_id"`
	ClientIP   string  `json:"client_ip"`
	Method     string  `json:"method"`
	Scheme     string  `json:"scheme,omitempty"`
	Host       string  `json:"host"`
	URI        string  `json:"uri"`
	Proto      string  `json:"proto"`
	Status     int     `json:"status"`
	Bytes      int64   `json:"bytes"`
	UpstreamMs float64 `json:"upstream_ms"`
	TotalMs    float64 `json:"total_ms"`
	UserAgent  string  `json:"user_agent,omitempty"`
	Referer    string  `json:"referer,omitempty"`
	Profile    string  `json:"profile"`
	Verdict    string  `json:"verdict"`
	Error      string  `json:"error,omitempty"`
}

// Access 写一条访问日志。写失败只能记到 stderr，绝不能让日志失败影响请求处理。
// 加锁由底层 lockedWriter 负责，这里不重复加锁。
func (l *Logger) Access(r AccessRecord) {
	if r.Ts == "" {
		r.Ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := l.enc.Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, "donothack: 写访问日志失败：%v\n", err)
	}
}

// NewTxID 生成 16 个十六进制字符的事务 ID，用于把同一次请求的日志串起来。
func NewTxID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand 失败是极端情况，退化为时间戳，绝不 panic。
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// Recorder 在一次请求的生命周期内累积日志字段。
// 数据面只写它，不读它；access log 在请求结束时一次性生成。
type Recorder struct {
	TxID       string
	StartedAt  time.Time
	UpstreamMs float64
	Verdict    string
	Err        string
}

type recorderKey struct{}

// WithRecorder 把 Recorder 放进 context。
func WithRecorder(ctx context.Context, r *Recorder) context.Context {
	return context.WithValue(ctx, recorderKey{}, r)
}

// RecorderFrom 从 context 取 Recorder，可能为 nil。
func RecorderFrom(ctx context.Context) *Recorder {
	if r, ok := ctx.Value(recorderKey{}).(*Recorder); ok {
		return r
	}
	return nil
}

// NewRecorder 创建一次请求的 Recorder。
func NewRecorder() *Recorder {
	return &Recorder{TxID: NewTxID(), StartedAt: time.Now(), Verdict: "pass"}
}

// Elapsed 返回自请求开始的总耗时（毫秒）。
func (r *Recorder) Elapsed() float64 {
	return float64(time.Since(r.StartedAt)) / float64(time.Millisecond)
}

// Package audit 负责结构化日志：应用日志走 slog，访问/审计日志走固定字段的 JSON Lines。
//
// 三类保护，缺一不可（低配 VPS 上日志把自己写死是真事）：
//  1. **轮转**：单文件到 max_size_mb 就归档，份数受 max_backups 限制。
//  2. **总配额**：整个日志目录受 total_max_mb 限制，超了删最旧的。
//  3. **磁盘水位**：磁盘剩余低于 min_free_mb 时直接丢弃日志并计数 ——
//     日志的价值远低于业务可用性，宁可丢日志也不能把盘写满。
//
// 另外访问日志支持三种策略（all / hit / sample）。压测实测：29k rps 全量记录
// 约 22 MB/s，所以这个开关不是可选项。
//
// 尚未实现（P4）：有界异步队列、命中事件 ring buffer 与分钟聚合桶。
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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options 是日志器的构造参数。
//
// 应用日志与访问/审计日志**默认分开**：前者走 stderr，后者走 stdout 或文件。
// 混在一个文件里会让"按字段过滤审计记录"变得别扭。
type Options struct {
	Level  string // debug | info | warn | error
	Format string // json | text

	// 访问 / 审计日志的去向
	Output string // stdout | file
	File   string

	// 应用日志的去向
	AppOutput string // stderr | stdout | file（空 = stderr）
	AppFile   string

	// 轮转与保留（只对 file 去向生效）
	MaxSizeMB  int  // 单文件上限
	MaxBackups int  // 保留份数
	TotalMaxMB int  // 日志目录总配额
	MinFreeMB  int  // 磁盘剩余水位
	Compress   bool // 轮转后 gzip

	// 访问日志策略
	AccessMode        string // all | hit | sample（空 = all）
	AccessSampleRatio int    // sample 模式下每 N 条记 1 条（默认 100）

	// Writer / AppWriter 覆盖对应去向，仅供测试与嵌入场景使用（此时不做轮转）。
	Writer    io.Writer
	AppWriter io.Writer
}

// Logger 同时提供应用日志与访问日志。
//
// 应用日志（slog）与访问日志（JSON Lines）可能写同一个文件，
// 因此两者必须共用同一把锁 —— 否则两行日志会交错，落盘内容不可解析。
type Logger struct {
	app *slog.Logger

	// mu 保护底层 writer。它只由 lockedWriter 获取：
	// 谁写谁加锁，调用方不要重复加锁（会自锁）。
	mu     sync.Mutex
	enc    *json.Encoder
	closer io.Closer

	// 轮转器（仅 file 去向）
	auditRotator *rotateWriter

	// 访问日志策略
	accessMode  string
	accessRatio int64

	accessSeen    atomic.Int64 // 参与采样的条数
	accessWritten atomic.Int64
	accessSkipped atomic.Int64
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

	appW, appCloser, err := openSink(o, o.AppOutput, o.AppFile, os.Stderr, o.AppWriter)
	if err != nil {
		return nil, fmt.Errorf("应用日志：%w", err)
	}
	auditW, auditCloser, err := openSink(o, o.Output, o.File, os.Stdout, o.Writer)
	if err != nil {
		if appCloser != nil {
			_ = appCloser.Close()
		}
		return nil, fmt.Errorf("访问日志：%w", err)
	}

	ratio := int64(o.AccessSampleRatio)
	if ratio <= 0 {
		ratio = 100
	}
	mode := o.AccessMode
	if mode == "" {
		mode = "all"
	}

	lg := &Logger{
		closer:      closerOf(appCloser, auditCloser),
		accessMode:  mode,
		accessRatio: ratio,
	}
	if rw, ok := auditW.(*rotateWriter); ok {
		lg.auditRotator = rw
	}
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

// openSink 解析 "stderr | stdout | file" 三种去向；file 走带轮转的 writer。
func openSink(o Options, output, file string, fallback io.Writer, override io.Writer) (io.Writer, io.Closer, error) {
	if override != nil {
		return override, nil, nil
	}
	switch output {
	case "", "default":
		return fallback, nil, nil
	case "stderr":
		return os.Stderr, nil, nil
	case "stdout":
		return os.Stdout, nil, nil
	case "file":
		if strings.TrimSpace(file) == "" {
			return nil, nil, fmt.Errorf("output=file 时文件路径必填")
		}
		rw, err := newRotateWriter(rotateOptions{
			Path:       file,
			MaxSize:    int64(o.MaxSizeMB) << 20,
			MaxBackups: o.MaxBackups,
			TotalMax:   int64(o.TotalMaxMB) << 20,
			MinFree:    int64(o.MinFreeMB) << 20,
			Compress:   o.Compress,
		})
		if err != nil {
			return nil, nil, err
		}
		return rw, rw, nil
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

// Close 关闭底层文件并等待压缩收尾。
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// Stats 汇总日志侧的运行事实，供 /readyz 与指标使用。
//
// 这些数字必须能被看到：日志被丢弃、旧文件被删除，如果没人知道，
// 出问题时就只剩"日志怎么少了一段"这种无法解释的现象。
type Stats struct {
	AuditDropped         int64 `json:"audit_dropped"`
	AuditRotations       int64 `json:"audit_rotations"`
	AuditDeletedFiles    int64 `json:"audit_deleted_files"`
	AuditSkippedCompress int64 `json:"audit_skipped_compress"`
	AccessSeen           int64 `json:"access_seen"`
	AccessWritten        int64 `json:"access_written"`
	AccessSkipped        int64 `json:"access_skipped"`
}

// Stats 返回统计。
func (l *Logger) Stats() Stats {
	var s Stats
	if l.auditRotator != nil {
		s.AuditDropped, s.AuditRotations, s.AuditSkippedCompress, s.AuditDeletedFiles = l.auditRotator.Stats()
	}
	s.AccessSeen = l.accessSeen.Load()
	s.AccessWritten = l.accessWritten.Load()
	s.AccessSkipped = l.accessSkipped.Load()
	return s
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

// shouldWrite 决定这条访问记录要不要落盘。
//
//   - all：全记
//   - hit：只记非 pass 的裁决（被拦、被限速、502 等）
//   - sample：非 pass 全记，pass 按 1/N 采样
func (l *Logger) shouldWrite(verdict string) bool {
	interesting := verdict != "" && verdict != "pass"
	switch l.accessMode {
	case "hit":
		return interesting
	case "sample":
		if interesting {
			return true
		}
		n := l.accessSeen.Add(1)
		if l.accessRatio <= 1 {
			return true
		}
		// 用计数器取模做采样：比每请求一次 rand 便宜得多，分布也均匀。
		return n%l.accessRatio == 1
	default:
		return true
	}
}

// Access 写一条访问日志。写失败只能记到 stderr，绝不能让日志失败影响请求处理。
// 加锁由底层 lockedWriter 负责，这里不重复加锁。
func (l *Logger) Access(r AccessRecord) {
	if !l.shouldWrite(r.Verdict) {
		l.accessSkipped.Add(1)
		return
	}
	if r.Ts == "" {
		r.Ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := l.enc.Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, "donothack: 写访问日志失败：%v\n", err)
		return
	}
	l.accessWritten.Add(1)
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

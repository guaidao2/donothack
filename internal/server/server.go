// Package server 装配数据面监听器：健康探针、并发连接上限、访问日志、优雅停机。
//
// 分层：server 负责编排与统计，proxy 负责转发，audit 负责输出。
// 一个请求的日志只在一个地方产生（instrument 中间件），避免重复计数。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"donothack/internal/audit"
	"donothack/internal/config"
	"donothack/internal/profile"
)

// Options 是数据面服务器的构造参数。
type Options struct {
	Config        *config.Config
	Profile       profile.Params
	ProfileName   profile.Name
	ProfileSource string
	Budget        profile.Budget
	Detection     profile.Detection
	MemLimit      int64 // 实际设置的 GOMEMLIMIT（字节，0 表示未设置）
	Logger        *audit.Logger
	Next          http.Handler // 数据面处理器（P0 = proxy）
	Version       string
}

// Server 是数据面服务器。
type Server struct {
	o Options

	// sem 是并发连接信号量。它保护的是内存：每个连接都有读缓冲、写缓冲与事务对象，
	// 连接数不设上限，攻击者用几千个半开连接就能把机器打挂。
	sem chan struct{}

	inflight atomic.Int64
	rejected atomic.Int64
	ready    atomic.Bool
	probe    *upstreamProbe

	startedAt time.Time
}

// New 构造服务器。
func New(o Options) *Server {
	return &Server{
		o:         o,
		sem:       make(chan struct{}, o.Config.Listen.MaxConns),
		probe:     newUpstreamProbe(o.Config.Upstream.URL),
		startedAt: time.Now(),
	}
}

// Ready 报告就绪状态。
func (s *Server) Ready() bool { return s.ready.Load() }

// Handler 返回完整的数据面 handler（供测试与 Serve 共用）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(s.o.Config.Listen.HealthPath, s.handleHealth)
	mux.HandleFunc(s.o.Config.Listen.ReadyPath, s.handleReady)
	mux.Handle("/", s.limited(s.o.Next))
	return s.instrument(mux)
}

// Serve 监听并在 ctx 取消时优雅停机。
func (s *Server) Serve(ctx context.Context) error {
	addr, err := s.o.Config.ListenAddr()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("监听 %s 失败：%w", addr, err)
	}
	s.o.Logger.App().Info("数据面已开始监听", "addr", ln.Addr().String())
	return s.ServeListener(ctx, ln)
}

// ServeListener 在给定的 listener 上服务，并在 ctx 取消时优雅停机。
// 单独抽出这一层是为了让"停机必须 drain 在途请求"这条验收项可以被自动化测试覆盖。
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	l := s.o.Config.Listen
	srv := &http.Server{
		Handler: s.Handler(),
		// 32 KiB 而不是 net/http 默认的 1 MiB：默认值在低配上是内存放大点。
		MaxHeaderBytes:    int(l.MaxHeaderBytes),
		ReadHeaderTimeout: l.ReadHeaderTimeout.D(),
		ReadTimeout:       l.ReadTimeout.D(),
		WriteTimeout:      l.WriteTimeout.D(),
		IdleTimeout:       l.IdleTimeout.D(),
		ErrorLog:          slog.NewLogLogger(s.o.Logger.App().Handler(), slog.LevelWarn),
	}

	s.ready.Store(true)
	s.o.Logger.App().Info("数据面已启动",
		"addr", ln.Addr().String(),
		"upstream", s.o.Config.Upstream.URL,
		"profile", string(s.o.ProfileName),
		"max_conns", l.MaxConns,
		"max_header_bytes", int64(l.MaxHeaderBytes),
		"engine_mode", s.o.Config.Engine.Mode,
	)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		// 先摘掉 ready，让前置负载均衡把流量移走，再 drain 在途请求。
		s.ready.Store(false)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), l.ShutdownTimeout.D())
		defer cancel()

		s.o.Logger.App().Info("开始优雅停机",
			"inflight", s.inflight.Load(),
			"timeout", l.ShutdownTimeout.String())

		if err := srv.Shutdown(shutdownCtx); err != nil {
			// 超时未 drain 完：强制关闭，但把事实记清楚。
			s.o.Logger.App().Warn("优雅停机超时，强制关闭", "err", err)
			_ = srv.Close()
			return fmt.Errorf("优雅停机超时：%w", err)
		}
		s.o.Logger.App().Info("已停机")
		return nil
	}
}

// instrument 是最外层中间件：分配事务 ID、统计状态与字节、结束写一条访问日志。
// 健康探针不写访问日志（否则日志会被探针刷满）。
func (s *Server) instrument(next http.Handler) http.Handler {
	health := s.o.Config.Listen.HealthPath
	ready := s.o.Config.Listen.ReadyPath

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == health || r.URL.Path == ready {
			next.ServeHTTP(w, r)
			return
		}

		rec := audit.NewRecorder()
		r = r.WithContext(audit.WithRecorder(r.Context(), rec))
		w.Header().Set("X-Request-ID", rec.TxID)

		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		s.o.Logger.Access(audit.AccessRecord{
			TxID:       rec.TxID,
			ClientIP:   clientIP(r),
			Method:     r.Method,
			Scheme:     schemeOf(r),
			Host:       r.Host,
			URI:        r.URL.RequestURI(),
			Proto:      r.Proto,
			Status:     rw.status,
			Bytes:      rw.bytes,
			UpstreamMs: round2(rec.UpstreamMs),
			TotalMs:    round2(rec.Elapsed()),
			UserAgent:  r.UserAgent(),
			Referer:    r.Referer(),
			Profile:    string(s.o.ProfileName),
			Verdict:    rec.Verdict,
			Error:      rec.Err,
		})
	})
}

// limited 实施并发连接上限。超限直接 503 并带上 Retry-After ——
// 拒绝服务比把内存吃穿好，也比静默排队让客户端超时好。
func (s *Server) limited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
			s.inflight.Add(1)
			defer s.inflight.Add(-1)
			next.ServeHTTP(w, r)
		default:
			n := s.rejected.Add(1)
			rec := audit.RecorderFrom(r.Context())
			if rec != nil {
				rec.Verdict = "rejected_busy"
				rec.Err = "并发连接已达上限"
			}
			if n == 1 || n%1000 == 0 {
				s.o.Logger.App().Warn("并发连接已达上限，开始拒绝请求",
					"max_conns", s.o.Config.Listen.MaxConns, "rejected_total", n)
			}
			w.Header().Set("Retry-After", "1")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "server busy\n")
		}
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

// ReadyInfo 是 /readyz 的响应体。它把所有"为什么是这个档位"的信息都摆出来，
// 免得运维靠猜。
type ReadyInfo struct {
	Status          string  `json:"status"`
	Version         string  `json:"version"`
	Profile         string  `json:"profile"`
	ProfileSource   string  `json:"profile_source"`
	NumCPU          int     `json:"num_cpu"`
	MemLimitBytes   int64   `json:"mem_limit_bytes"`
	MemLimitSource  string  `json:"mem_limit_source"`
	GOMEMLIMIT      int64   `json:"gomemlimit_bytes"`
	GOGC            int     `json:"gogc"`
	BudgetMiB       float64 `json:"budget_mib"`
	BudgetTargetMiB float64 `json:"budget_target_mib"`
	Upstream        string  `json:"upstream"`
	UpstreamOK      bool    `json:"upstream_ok"`
	UpstreamDetail  string  `json:"upstream_detail,omitempty"`
	MaxConns        int     `json:"max_conns"`
	Inflight        int64   `json:"inflight"`
	RejectedTotal   int64   `json:"rejected_total"`
	Ruleset         string  `json:"ruleset"`
	UptimeSeconds   float64 `json:"uptime_seconds"`
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ok, detail := s.probe.check(r.Context())

	info := ReadyInfo{
		Status:          "ok",
		Version:         s.o.Version,
		Profile:         string(s.o.ProfileName),
		ProfileSource:   s.o.ProfileSource,
		NumCPU:          s.o.Detection.NumCPU,
		MemLimitBytes:   s.o.Detection.MemBytes,
		MemLimitSource:  s.o.Detection.MemSource,
		GOMEMLIMIT:      s.o.MemLimit,
		GOGC:            s.o.Profile.GOGC,
		BudgetMiB:       round2(s.o.Budget.TotalMiB),
		BudgetTargetMiB: round2(s.o.Budget.TargetMiB),
		Upstream:        s.o.Config.Upstream.URL,
		UpstreamOK:      ok,
		UpstreamDetail:  detail,
		MaxConns:        s.o.Config.Listen.MaxConns,
		Inflight:        s.inflight.Load(),
		RejectedTotal:   s.rejected.Load(),
		// 规则集要到 P2 才有。这里如实说明，不假装就绪。
		Ruleset:       "not-implemented-until-P2（P0 只做转发，不做检测）",
		UptimeSeconds: round2(time.Since(s.startedAt).Seconds()),
	}

	healthy := ok && s.ready.Load()
	if !healthy {
		info.Status = "unavailable"
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}

func round2(f float64) float64 { return float64(int64(f*100+0.5)) / 100 }

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// statusRecorder 统计状态码与字节数，并实现 Unwrap 让 http.ResponseController
// 能找到内层 ResponseWriter（Flush 与 WebSocket 升级都依赖它）。
type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int64
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// ReadFrom 保留 io.Copy 的零拷贝快路径（Linux 上 net.TCPConn 可走 splice）。
func (r *statusRecorder) ReadFrom(src io.Reader) (int64, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	if rf, ok := r.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(src)
		r.bytes += n
		return n, err
	}
	n, err := io.Copy(r.ResponseWriter, src)
	r.bytes += n
	return n, err
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// upstreamProbe 缓存上游主机的解析结果，供 /readyz 判断"上游是否可达"。
// 缓存 30 秒：既不阻塞每个探针，也不至于让 DNS 抖动直接翻成 503。
type upstreamProbe struct {
	host string
	port string

	mu     sync.Mutex
	lastOK bool
	detail string
	lastAt time.Time
}

func newUpstreamProbe(rawURL string) *upstreamProbe {
	host, port := rawURL, ""
	if h, p, err := net.SplitHostPort(rawURL); err == nil {
		host, port = h, p
	} else {
		host = rawURL
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		if j := strings.IndexAny(host, "/?#"); j >= 0 {
			host = host[:j]
		}
		if h, p, err := net.SplitHostPort(host); err == nil {
			host, port = h, p
		}
	}
	return &upstreamProbe{host: host, port: port}
}

const probeTTL = 30 * time.Second

func (p *upstreamProbe) check(ctx context.Context) (bool, string) {
	p.mu.Lock()
	if time.Since(p.lastAt) < probeTTL {
		ok, detail := p.lastOK, p.detail
		p.mu.Unlock()
		return ok, detail
	}
	p.mu.Unlock()

	ok, detail := p.resolve(ctx)

	p.mu.Lock()
	p.lastOK, p.detail, p.lastAt = ok, detail, time.Now()
	p.mu.Unlock()
	return ok, detail
}

func (p *upstreamProbe) resolve(ctx context.Context) (bool, string) {
	host := p.host
	if host == "" {
		return false, "上游主机为空"
	}
	if net.ParseIP(host) != nil {
		return true, "上游主机是 IP 字面量"
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return false, fmt.Sprintf("上游 DNS 解析失败：%v", err)
	}
	return true, fmt.Sprintf("上游 DNS 解析到 %v", addrs)
}

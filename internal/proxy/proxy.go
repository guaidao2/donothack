// Package proxy 是数据面的反向代理。
//
// P0 职责：把请求原样转发给上游，把响应原样流式回传。日志与统计由 server 统一负责，
// 本包只把过程中的事实写进请求的 audit.Recorder。
//
// 三条设计约束（docs/DESIGN.md §3、§1 非目标、PERFORMANCE.md §6）：
//  1. **响应完全不进内存**：不做响应侧检测，因此不需要 body tee，也不需要缓冲。
//  2. **上游不可达时返回 502，绝不静默直连** —— 那等于凭空绕过 WAF。
//  3. **不信任 X-Forwarded-For**：严格信任链在 P3 的 realip 模块实现；
//     在那之前宁可用连接对端地址，也不要被伪造头带偏（限速与封禁都依赖它）。
package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"donothack/internal/audit"
)

// Options 是代理的构造参数。
type Options struct {
	Upstream              *url.URL
	PreserveHost          bool
	DialTimeout           time.Duration
	ResponseHeaderTimeout time.Duration
	IdleConnTimeout       time.Duration
	MaxIdleConnsPerHost   int
}

// Proxy 实现 http.Handler。
type Proxy struct {
	rp *httputil.ReverseProxy
}

// New 构造代理。Transport 按低配预算调优，所有超时显式设置。
func New(o Options) *Proxy {
	dialer := &net.Dialer{
		Timeout:   o.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	tr := &http.Transport{
		// 不使用环境变量里的代理：出网行为必须可控，否则线上排查会被 HTTP_PROXY 坑。
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          max(2, o.MaxIdleConnsPerHost*2),
		MaxIdleConnsPerHost:   o.MaxIdleConnsPerHost,
		IdleConnTimeout:       o.IdleConnTimeout,
		ResponseHeaderTimeout: o.ResponseHeaderTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		// 不自己加 Accept-Encoding：客户端请求头原样透传，
		// 由客户端与上游决定压缩，避免代理层插入第二层编码。
		DisableCompression: true,
	}

	p := &Proxy{}
	p.rp = &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(o.Upstream)
			// SetXForwarded 安全地追加客户端 IP，并设置 X-Forwarded-Host / X-Forwarded-Proto。
			pr.SetXForwarded()
			if rec := audit.RecorderFrom(pr.In.Context()); rec != nil {
				pr.Out.Header.Set("X-Request-ID", rec.TxID)
			}
			if o.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
		},
		ModifyResponse: func(res *http.Response) error {
			// 客户端看到的 X-Request-ID 必须是我们分配的那一个。
			// 上游可能也带同名头（或被我们透传后又回显），不清掉就会变成两个值。
			res.Header.Del("X-Request-ID")
			// 记录"请求开始 → 上游响应头到达"的耗时。
			// P0 没有检测环节，这个值基本等于上游耗时；P2 之后它含解析与规则评估，字段名不变。
			if rec := audit.RecorderFrom(res.Request.Context()); rec != nil {
				rec.UpstreamMs = float64(time.Since(rec.StartedAt)) / float64(time.Millisecond)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if rec := audit.RecorderFrom(r.Context()); rec != nil {
				rec.Verdict = "bad_gateway"
				rec.Err = err.Error()
			}
			// 不把上游地址与内部错误细节回给客户端；细节进访问日志。
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "upstream unavailable\n")
		},
	}
	return p
}

// ServeHTTP 转发请求。它不包装 ResponseWriter、不写日志 —— 那样会与 server 的统计重复。
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.rp.ServeHTTP(w, r)
}

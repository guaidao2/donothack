// Package pipeline 把检测引擎与反向代理串成数据面的完整处理器。
//
// 顺序：解析 → 检测 → 决策 → 放行（转发）或拦截（就地返回）。
//
// 三条不变量：
//  1. **fail-open**：引擎出错就放行并记审计，绝不因为 WAF 自己出错而给业务 5xx。
//  2. **拦截响应最小化**：不回显命中的 payload，只回一个状态码与事务 ID。
//  3. **决策可追溯**：每个请求的裁决与命中事件都进日志，且带上规则集版本。
package pipeline

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"sync"

	"donothack/internal/audit"
	"donothack/internal/engine"
	"donothack/internal/rules"
	"donothack/internal/tx"
)

// Options 是流水线构造参数。
type Options struct {
	Engine *engine.Engine
	Next   http.Handler // 数据面处理器（P2 起就是反向代理）
	Logger *audit.Logger
	// FailMode: open（默认，出错放行）| closed（出错拦截）
	FailMode string
	// BlockStatus 是拦截时返回的状态码（默认 403）。
	BlockStatus int
}

// Pipeline 实现 http.Handler。
type Pipeline struct {
	o Options

	pool sync.Pool
}

// New 构造流水线。
func New(o Options) *Pipeline {
	if o.BlockStatus == 0 {
		o.BlockStatus = http.StatusForbidden
	}
	if o.FailMode == "" {
		o.FailMode = "open"
	}
	p := &Pipeline{o: o}
	p.pool.New = func() any { return &tx.Transaction{} }
	return p
}

// ServeHTTP 实现数据面主流程。
func (p *Pipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := audit.RecorderFrom(r.Context())

	t := p.pool.Get().(*tx.Transaction)
	defer func() {
		t.Reset()
		p.pool.Put(t)
	}()
	if rec != nil {
		t.ID = rec.TxID
	}
	t.ClientIP = clientIP(r)

	dec, err := p.o.Engine.Process(r.Context(), t, r)
	if err != nil {
		// fail-open：引擎自己出错不能拖垮业务。
		if p.o.Logger != nil {
			p.o.Logger.App().Error("检测引擎出错，按 fail-open 放行",
				"tx_id", t.ID, "fail_mode", p.o.FailMode, "err", err)
		}
		if rec != nil {
			rec.Verdict = "engine_error"
			rec.Err = err.Error()
		}
		if p.o.FailMode == "closed" {
			p.reject(w, t, http.StatusServiceUnavailable, "engine unavailable")
			return
		}
		p.forward(w, r)
		return
	}

	if rec != nil {
		rec.Verdict = dec.Verdict.String()
		if len(dec.Events) > 0 {
			rec.RuleID = dec.RuleID
			rec.Score = dec.Score
		}
	}
	if p.o.Logger != nil && len(dec.Events) > 0 {
		p.logEvents(t, dec)
	}

	if dec.Verdict == tx.VerdictBlock || dec.Verdict == tx.VerdictDrop {
		p.respondBlocked(w, t, dec)
		return
	}
	p.forward(w, r)
}

func (p *Pipeline) forward(w http.ResponseWriter, r *http.Request) {
	if p.o.Next == nil {
		http.Error(w, "no upstream configured", http.StatusBadGateway)
		return
	}
	p.o.Next.ServeHTTP(w, r)
}

// respondBlocked 就地返回拦截响应。
//
// 注意：**不回显命中的 payload**，也不回显规则细节 —— 那既是信息泄露，
// 也会把 WAF 变成反射型 XSS 的帮凶。只给状态码与事务 ID。
func (p *Pipeline) respondBlocked(w http.ResponseWriter, t *tx.Transaction, dec engine.Decision) {
	status := dec.Status
	if status == 0 || status == 200 {
		status = p.o.BlockStatus
	}
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Request-ID", t.ID)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "Request blocked by donothack\n")
}

func (p *Pipeline) reject(w http.ResponseWriter, t *tx.Transaction, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Request-ID", t.ID)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}

// logEvents 把命中事件写进应用日志。
//
// 只记"目标名 + 算子 + 指纹描述"，**不记 payload 原文** ——
// 审计日志不该成为敏感数据泄露点，也不该被 payload 撑爆。
func (p *Pipeline) logEvents(t *tx.Transaction, dec engine.Decision) {
	rs := p.o.Engine.RuleSet()
	ver := ""
	if rs != nil {
		ver = rs.Version
	}
	attrs := make([]any, 0, 24)
	attrs = append(attrs,
		"tx_id", t.ID,
		"client_ip", t.ClientIP,
		"method", t.Vars.Method,
		"path", t.Vars.Path,
		"verdict", dec.Verdict.String(),
		"score", dec.Score,
		"mode", dec.Mode,
		"ruleset", ver,
		"events", len(dec.Events),
	)
	for i, ev := range dec.Events {
		if i >= 4 { // 每个请求最多展开 4 条，避免日志被刷爆
			break
		}
		attrs = append(attrs,
			"rule_"+strconv.Itoa(i), ev.RuleID,
			"cat_"+strconv.Itoa(i), ev.Category,
			"target_"+strconv.Itoa(i), ev.Target,
			"detail_"+strconv.Itoa(i), ev.Detail,
		)
	}
	p.o.Logger.App().Info("命中", attrs...)
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

var _ = context.Background
var _ = rules.DefaultCategories

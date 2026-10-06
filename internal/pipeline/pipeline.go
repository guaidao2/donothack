// Package pipeline 把检测引擎、限速、降级与反向代理串成数据面的完整处理器。
//
// 一个请求的完整路径：
//
//	真实 IP 解析 → 降级检查 → 限速/封禁 → 检测引擎 → 裁决 → 拦截页 或 转发
//
// 四条不变量：
//  1. **fail-open**：引擎出错就放行并记审计，绝不因为 WAF 自己出错而给业务 5xx。
//  2. **拦截响应最小化**：不暴露规则细节与命中位置，只给请求 ID 让用户能报障。
//  3. **决策可追溯**：裁决、命中事件、限速状态都进日志，且带规则集版本。
//  4. **降级不静默**：block 模式下检测能力下降就返回 503，绝不放行未经检测的流量。
package pipeline

import (
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"donothack/internal/audit"
	"donothack/internal/blockpage"
	"donothack/internal/degrade"
	"donothack/internal/engine"
	"donothack/internal/eventstore"
	"donothack/internal/ratelimit"
	"donothack/internal/realip"
	"donothack/internal/tx"
)

// Options 是流水线构造参数。
type Options struct {
	Engine *engine.Engine
	Next   http.Handler // 数据面处理器（反向代理）
	Logger *audit.Logger

	// FailMode: open（默认，出错放行）| closed（出错拦截）
	FailMode string

	// BlockPage 是拦截页渲染器（nil 则用内置默认）。
	BlockPage *blockpage.Renderer
	// Limiter 是限速器（nil 或未启用则不限速）。
	Limiter *ratelimit.Limiter
	// Resolver 是真实 IP 解析器（nil 则直接用对端地址）。
	Resolver *realip.Resolver
	// Degrader 是过载降级器（nil 则不检查）。
	Degrader *degrade.Degrader

	// BanOnBlock 表示检测引擎判定拦截时，是否同时临时封禁来源 IP。
	BanOnBlock bool
	// BlockBanDuration 是上面那个封禁的时长。
	BlockBanDuration time.Duration
	// MaxTarpit 是 tarpit 动作的最长延迟（防止把连接池拖死）。
	MaxTarpit time.Duration

	// Events 是内存事件存储（控制台的数据源）。nil 表示不记录。
	//
	// **只记"有检测结果"的请求**（命中或非放行裁决），不记纯放行的请求 ——
	// 它是检测事件存储，不是访问日志（访问日志在 audit 里）。
	Events *eventstore.Store
}

// Pipeline 实现 http.Handler。
type Pipeline struct {
	o Options

	pool sync.Pool

	// blockPage 可被控制台热替换
	blockPage atomic.Pointer[blockpage.Renderer]

	blockedTotal atomic.Uint64
	rateLimited  atomic.Uint64
	rejected     atomic.Uint64
	engineErrors atomic.Uint64
	tarpitted    atomic.Uint64
}

// Stats 是数据面统计。
type Stats struct {
	Blocked      uint64
	RateLimited  uint64
	Rejected503  uint64
	EngineErrors uint64
	Tarpitted    uint64
}

// Stats 返回统计快照。
func (p *Pipeline) Stats() Stats {
	return Stats{
		Blocked:      p.blockedTotal.Load(),
		RateLimited:  p.rateLimited.Load(),
		Rejected503:  p.rejected.Load(),
		EngineErrors: p.engineErrors.Load(),
		Tarpitted:    p.tarpitted.Load(),
	}
}

// page 返回当前拦截页渲染器（可被控制台热替换）。
func (p *Pipeline) page() *blockpage.Renderer {
	if r := p.blockPage.Load(); r != nil {
		return r
	}
	return p.o.BlockPage
}

// New 构造流水线。
func New(o Options) *Pipeline {
	if o.FailMode == "" {
		o.FailMode = "open"
	}
	if o.BlockPage == nil {
		o.BlockPage = blockpage.New(blockpage.Options{})
	}
	if o.MaxTarpit <= 0 {
		o.MaxTarpit = 3 * time.Second
	}
	if o.BlockBanDuration <= 0 {
		o.BlockBanDuration = 5 * time.Minute
	}
	pl := &Pipeline{o: o}
	pl.pool.New = func() any { return &tx.Transaction{} }
	pl.blockPage.Store(o.BlockPage)
	return pl
}

// SetBlockPage 热替换拦截页渲染器（控制台改完拦截页后调用）。
//
// 用原子指针：在途请求要么用旧渲染器要么用新的，不会看到半成品。
func (p *Pipeline) SetBlockPage(r *blockpage.Renderer) {
	if r != nil {
		p.blockPage.Store(r)
	}
}

// ClientIP 从请求里解析真实客户端 IP（也供审计使用）。
func (p *Pipeline) ClientIP(r *http.Request) realip.Result {
	if p.o.Resolver == nil {
		return realip.Result{IP: peerAddr(r.RemoteAddr), Peer: peerAddr(r.RemoteAddr), Source: "peer"}
	}
	return p.o.Resolver.Resolve(r.RemoteAddr, r.Header)
}

// ServeHTTP 实现数据面主流程。
func (p *Pipeline) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := audit.RecorderFrom(r.Context())

	// ---- 1) 真实 IP ----
	ipRes := p.ClientIP(r)
	if rec != nil {
		rec.ClientIP = ipRes.IP
		if len(ipRes.Chain) > 0 {
			rec.ProxyChain = ipRes.Chain
		}
	}

	// ---- 2) 降级检查 ----
	// block/mixed 模式下检测能力一旦下降，宁可 503 也不放行未经检测的流量。
	if p.o.Degrader != nil && p.o.Degrader.ShouldReject() {
		p.rejected.Add(1)
		st := p.o.Degrader.Stats()
		p.record(&tx.Transaction{ID: txIDFrom(rec), ClientIP: ipRes.IP}, engine.Decision{
			Verdict: tx.VerdictBlock, Mode: "degraded",
		}, ipRes, http.StatusServiceUnavailable, "检测能力降级："+st.Level)
		if rec != nil {
			rec.Verdict = "rejected_degraded"
			rec.Reason = st.Level + "：" + st.Reason
		}
		w.Header().Set("Retry-After", "5")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("donothack: 检测能力已降级（" + st.Level + "），为保证安全暂不转发\n"))
		return
	}

	// ---- 3) 限速与封禁 ----
	if p.o.Limiter != nil && p.o.Limiter.Enabled() {
		if d := p.o.Limiter.Allow(ipRes.IP); !d.Allowed {
			p.rateLimited.Add(1)
			status := http.StatusTooManyRequests
			category := "ratelimit"
			if d.Banned {
				category = "ban"
			}
			retry := int(d.RetryAfter.Seconds())
			if retry <= 0 {
				retry = 1
			}
			if rec != nil {
				rec.Verdict = "ratelimit"
				rec.Reason = d.Reason
				rec.Status = status
			}
			p.record(&tx.Transaction{ID: txIDFrom(rec), ClientIP: ipRes.IP,
				Vars: tx.Collections{Method: r.Method, Path: r.URL.Path, Host: r.Host, UserAgent: r.UserAgent()},
			}, engine.Decision{Verdict: tx.VerdictBlock, Events: []tx.Event{{
				Category: category, Detail: d.Reason, RuleID: "RATE-LIMIT",
			}}}, ipRes, status, d.Reason)

			// 封禁/限速是**洪泛路径**：每秒可能几千个请求，
			// 这里强制走纯文本，不做模板渲染。
			p.page().Respond(w, r, p.page().NewData(
				r, txIDFrom(rec), category, "", ipRes.IP, status, retry), true)
			return
		}
	}

	// ---- 4) 检测 ----
	t := p.pool.Get().(*tx.Transaction)
	defer func() {
		t.Reset()
		p.pool.Put(t)
	}()
	if rec != nil {
		t.ID = rec.TxID
	}
	t.ClientIP = ipRes.IP

	dec, err := p.o.Engine.Process(r.Context(), t, r)
	if err != nil {
		p.engineErrors.Add(1)
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
			p.page().Respond(w, r, p.page().NewData(
				r, t.ID, "protocol", "", ipRes.IP, http.StatusServiceUnavailable, 0), true)
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

	// ---- 5) 处置 ----
	switch dec.Verdict {
	case tx.VerdictDrop:
		p.record(t, dec, ipRes, 0, dec.Reason)
		// drop 是最高档：**不回任何响应，直接断连**。
		// 它对扫描器最不友好（拿不到状态码、拿不到页面、也拿不到规则反馈），
		// 但正常用户会看到"连接被重置"，所以只该给明确的恶意流量用。
		p.blockedTotal.Add(1)
		if p.drop(w) {
			return
		}
		// HTTP/2 等不支持 Hijack 的场景退化为拦截页，而不是悄悄放行。
		p.respondBlocked(w, r, t, dec, ipRes.IP)

	case tx.VerdictBlock:
		p.blockedTotal.Add(1)
		p.record(t, dec, ipRes, dec.Status, dec.Reason)
		if p.o.BanOnBlock && p.o.Limiter != nil {
			p.o.Limiter.Ban(ipRes.IP, p.o.BlockBanDuration)
		}
		p.respondBlocked(w, r, t, dec, ipRes.IP)

	case tx.VerdictTarpit:
		p.tarpitted.Add(1)
		p.record(t, dec, ipRes, 200, dec.Reason)
		// 拖时间是对攻击者的成本压制，但**必须有上限**：
		// 无上限的延迟会把自己的连接池与 goroutine 拖死，那是自伤。
		p.tarpit(dec)
		p.forward(w, r)

	case tx.VerdictChallenge:
		// 挑战动作需要前端配合（JS + 签名 cookie）。未实现时**降级为拦截**，
		// 而不是放行 —— 放行等于让 challenge 规则形同不存在。
		p.blockedTotal.Add(1)
		p.record(t, dec, ipRes, dec.Status, dec.Reason)
		p.respondBlocked(w, r, t, dec, ipRes.IP)

	default:
		// 命中但未达阈值（detect 模式或 log 动作）：记事件但不拦
		if len(dec.Events) > 0 {
			p.record(t, dec, ipRes, 200, dec.Reason)
		}
		p.forward(w, r)
	}
}

// drop 断连。返回 false 表示当前连接不支持（如 HTTP/2），调用方需退化处理。
func (p *Pipeline) drop(w http.ResponseWriter) bool {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return false
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// record 把一次检测结果写进内存事件存储。
//
// 只在"有东西可看"时记录：命中过、或裁决不是放行。纯放行请求不进 ring ——
// 否则 ring 会被正常流量冲掉，真正要看的事件反而留不住。
func (p *Pipeline) record(t *tx.Transaction, dec engine.Decision, ipRes realip.Result,
	status int, reason string) {
	if p.o.Events == nil {
		return
	}
	if len(dec.Events) == 0 && dec.Verdict == tx.VerdictPass {
		return
	}

	e := eventstore.Event{
		TxID:       t.ID,
		ClientIP:   ipRes.IP,
		Method:     t.Vars.Method,
		Host:       t.Vars.Host,
		Path:       t.Vars.Path,
		Proto:      t.Vars.Proto,
		Status:     status,
		Verdict:    dec.Verdict.String(),
		Score:      dec.Score,
		Mode:       dec.Mode,
		UserAgent:  t.Vars.UserAgent,
		ProxyChain: ipRes.Chain,
	}
	if rs := p.o.Engine.RuleSet(); rs != nil {
		e.Ruleset = rs.Version
	}
	if reason != "" {
		e.Message = reason
	}
	// 主导命中：分数最高的那条（与拦截页上展示的类目保持一致）
	best := -1
	for i, ev := range dec.Events {
		hit := eventstore.HitRef{
			RuleID: ev.RuleID, Category: ev.Category, Severity: ev.Severity.String(),
			Target: ev.Target, Detail: ev.Detail, Score: ev.Score,
		}
		e.Hits = append(e.Hits, hit)
		if best < 0 || ev.Score > dec.Events[best].Score {
			best = i
		}
	}
	if best >= 0 {
		ev := dec.Events[best]
		e.RuleID = ev.RuleID
		e.Category = ev.Category
		e.Severity = ev.Severity.String()
		e.Target = ev.Target
		e.Operator = ev.Operator
		e.Detail = ev.Detail
		e.MatchedLen = ev.MatchedLen
		if len(ev.PayloadBefore) > 0 {
			e.PayloadBefore = string(ev.PayloadBefore)
		}
		if len(ev.PayloadAfter) > 0 {
			e.PayloadAfter = string(ev.PayloadAfter)
		}
	}
	p.o.Events.Add(e)
}

// respondBlocked 用拦截页响应。
func (p *Pipeline) respondBlocked(w http.ResponseWriter, r *http.Request, t *tx.Transaction, dec engine.Decision, ip string) {
	status := dec.Status
	if status == 0 || status == 200 {
		status = http.StatusForbidden
	}
	category, ruleID := dominantCategory(dec)
	d := p.page().NewData(r, t.ID, category, ruleID, ip, status, 0)
	p.page().Respond(w, r, d, false)
}

// dominantCategory 取分数最高的类目（决定页面上写"命中了什么"）。
//
// 用最高分而不是第一条命中：一条规则链里可能先是低分探测再是高分攻击，
// 页面上写"扫描器探测"而实际是 SQL 注入，会让用户困惑。
func dominantCategory(dec engine.Decision) (string, string) {
	best, bestScore := "", -1
	ruleID := ""
	for _, ev := range dec.Events {
		if ev.Score > bestScore {
			best, bestScore, ruleID = ev.Category, ev.Score, ev.RuleID
		}
	}
	if best == "" && len(dec.Events) > 0 {
		best = dec.Events[0].Category
		ruleID = dec.Events[0].RuleID
	}
	return best, ruleID
}

// tarpit 拖延响应时间（有上限）。
func (p *Pipeline) tarpit(dec engine.Decision) {
	d := 2 * time.Second
	if p.o.MaxTarpit > 0 && d > p.o.MaxTarpit {
		d = p.o.MaxTarpit
	}
	time.Sleep(d)
}

func (p *Pipeline) forward(w http.ResponseWriter, r *http.Request) {
	if p.o.Next == nil {
		http.Error(w, "no upstream configured", http.StatusBadGateway)
		return
	}
	p.o.Next.ServeHTTP(w, r)
}

// logEvents 把命中事件写进应用日志。
//
// 只记"目标名 + 算子 + 指纹描述"，**不记 payload 原文** ——
// 审计日志不该成为敏感数据泄露点，也不该被 payload 撑爆。
func (p *Pipeline) logEvents(t *tx.Transaction, dec engine.Decision) {
	ver := ""
	if rs := p.o.Engine.RuleSet(); rs != nil {
		ver = rs.Version
	}
	attrs := make([]any, 0, 32)
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
		idx := strconv.Itoa(i)
		attrs = append(attrs,
			"rule_"+idx, ev.RuleID,
			"cat_"+idx, ev.Category,
			"target_"+idx, ev.Target,
			"detail_"+idx, ev.Detail,
		)
	}
	p.o.Logger.App().Info("命中", attrs...)
}

func txIDFrom(rec *audit.Recorder) string {
	if rec == nil {
		return ""
	}
	return rec.TxID
}

func peerAddr(remoteAddr string) string {
	for i := len(remoteAddr) - 1; i >= 0; i-- {
		if remoteAddr[i] == ':' {
			return remoteAddr[:i]
		}
	}
	return remoteAddr
}

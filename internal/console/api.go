package console

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"time"

	"donothack/internal/blockpage"
	"donothack/internal/control"
	"donothack/internal/eventstore"
	"donothack/internal/rules"
)

// authEvent 是一条控制台自身的操作记录（登录、改配置…）。
type authEvent struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	OK     bool      `json:"ok"`
	Remote string    `json:"remote,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

var (
	authLogMu sync.Mutex
	authLog   []authEvent
)

const authLogCapacity = 256

func recordAuth(e authEvent) {
	authLogMu.Lock()
	defer authLogMu.Unlock()
	if e.At.IsZero() {
		e.At = time.Now()
	}
	authLog = append(authLog, e)
	if len(authLog) > authLogCapacity {
		authLog = authLog[len(authLog)-authLogCapacity:]
	}
}

func authEvents(limit int) []authEvent {
	authLogMu.Lock()
	defer authLogMu.Unlock()
	n := len(authLog)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]authEvent, 0, limit)
	for i := n - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, authLog[i])
	}
	return out
}

// ---------------------------------------------------------------- 认证

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin 处理登录。
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "登录必须用 POST", "")
		return
	}
	ip := s.clientIP(r)

	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
		return
	}

	wantUser := s.o.Config.Admin.Username
	if strings.TrimSpace(wantUser) == "" {
		wantUser = "admin"
	}

	// 用户名与密码任一不对都给**同一个错误**：不告诉攻击者"用户名对了密码错了"。
	userOK := subtleEqual(req.Username, wantUser)
	// 无论用户名对不对都跑一次 PBKDF2，避免时间侧信道。
	passOK := verifyPassword(s.login.get(), req.Password)
	if !userOK || !passOK {
		s.loginFails.Add(1)
		if s.o.Limiter != nil {
			banned, until := s.o.Limiter.Penalize("console:" + ip)
			if banned {
				recordAuth(authEvent{Actor: req.Username, Action: "login", OK: false,
					Remote: ip, Detail: fmt.Sprintf("失败次数过多，封禁至 %s", until.Format(time.RFC3339))})
				s.writeError(w, http.StatusTooManyRequests, "locked_out",
					"尝试次数过多，已临时封禁", "")
				return
			}
		}
		recordAuth(authEvent{Actor: req.Username, Action: "login", OK: false, Remote: ip})
		s.writeError(w, http.StatusUnauthorized, "invalid_credentials", "用户名或密码不对", "")
		return
	}

	idle := s.o.Config.Admin.SessionIdleTimeout.D()
	if idle <= 0 {
		idle = 2 * time.Hour
	}
	id, csrf, err := s.session.create(wantUser, ip, r.UserAgent(), idle)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "session_failed", "创建会话失败", err.Error())
		return
	}

	secure := s.tlsEnabled()
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: s.cookiePath(),
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode,
	})
	// CSRF 用**双提交 + 签名**：cookie 里的值带 HMAC，前端读出来放进请求头。
	http.SetCookie(w, &http.Cookie{
		Name: csrfCookie, Value: signCSRF(s.secret, csrf), Path: s.cookiePath(),
		HttpOnly: false, // 前端要读它放进请求头
		Secure:   secure, SameSite: http.SameSiteStrictMode,
	})
	s.logins.Add(1)
	recordAuth(authEvent{Actor: wantUser, Action: "login", OK: true, Remote: ip})

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "user": wantUser, "csrf": csrf, "expires_in": int(idle.Seconds()),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "登出必须用 POST", "")
		return
	}
	if sess, ok := s.currentSession(r); ok {
		recordAuth(authEvent{Actor: sess.User, Action: "logout", OK: true, Remote: s.clientIP(r)})
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.session.drop(c.Value)
	}
	secure := s.tlsEnabled()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: s.cookiePath(), MaxAge: -1, HttpOnly: true, Secure: secure})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: s.cookiePath(), MaxAge: -1, Secure: secure})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSession 返回当前会话状态（前端启动时问一次）。
//
// **未登录时返回 401，而不是 200 + `authenticated:false`。**
// 这条契约踩过一次：前端按"401 = 未登录"判断（与其它所有端点一致），
// 而这里先返回的是 200，于是前端以为已登录、去挂载仪表盘、吃到一串 401，
// 首屏就显示"会话已过期"。保持全站一个约定比省一个状态码重要。
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "尚未登录", "")
		return
	}
	idle := s.o.Config.Admin.SessionIdleTimeout.D()
	if idle <= 0 {
		idle = 2 * time.Hour
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":  true,
		"user":           sess.User,
		"username":       sess.User,
		"actor":          sess.User,
		"csrf":           sess.CSRF,
		"expires_at":     sess.Expires.Format(time.RFC3339),
		"idle_timeout_s": int(idle.Seconds()),
		"totp_enabled":   s.o.Config.Admin.TOTPEnabled,
		"version":        s.o.Version,
		"snapshot":       s.snapshotVersion(),
	})
}

type passwordRequest struct {
	Old string `json:"old_password"`
	New string `json:"new_password"`
}

// handlePassword 改登录密码。
func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	sess, _ := s.currentSession(r)
	var req passwordRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
		return
	}
	if !verifyPassword(s.login.get(), req.Old) {
		recordAuth(authEvent{Actor: sess.User, Action: "password", OK: false, Remote: s.clientIP(r), Detail: "旧密码不对"})
		s.writeError(w, http.StatusUnauthorized, "invalid_credentials", "旧密码不对", "")
		return
	}
	if len(req.New) < 12 {
		s.writeError(w, http.StatusBadRequest, "weak_password", "新密码至少 12 位", "")
		return
	}
	hash, err := hashPassword(req.New)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "hash_failed", "生成密码哈希失败", err.Error())
		return
	}
	s.login.set(hash)
	// **改密码后所有会话立刻失效**：否则泄露的旧会话还能继续用。
	n := s.session.dropAll()
	recordAuth(authEvent{Actor: sess.User, Action: "password", OK: true, Remote: s.clientIP(r),
		Detail: fmt.Sprintf("已注销 %d 个会话", n)})
	writeJSON(w, http.StatusOK, okResponse{OK: true, Warnings: []string{
		fmt.Sprintf("密码已更新，已注销 %d 个会话（包括当前会话），请重新登录", n),
		"注意：这个密码只存在内存里，重启后会回到配置文件里的旧值 —— 要持久化请把新哈希写进 admin.password_hash",
	}})
}

// ---------------------------------------------------------------- 状态与统计

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	// 这个响应的字段名是**对着前端 dashboard 的取值写的**（前端用 pick() 做了容错，
	// 但容错不等于给全：缺字段会显示成 "—"，运维看不出是没数据还是坏了）。
	// 所以这里把顶层的、嵌套的、以及别名一并给全。
	out := map[string]any{
		"status":   "ok",
		"version":  s.o.Version,
		"now":      nowISO(),
		"snapshot": s.snapshotVersion(),
		"mount":    s.mount,
		"num_cpu":  runtime.NumCPU(),
		// GOMAXPROCS 与 NumCPU 不一定相等（可能被环境变量限制），要如实报。
		"gomaxprocs":     runtime.GOMAXPROCS(0),
		"goroutines":     runtime.NumGoroutine(),
		"uptime_seconds": 0.0,
		"uptime_s":       0.0,
	}

	// 就绪信息（档位、内存上限、上游健康、运行时长、日志计数）
	if s.o.ReadyInfo != nil {
		for k, v := range s.o.ReadyInfo() {
			out[k] = v
		}
	}
	if v, ok := out["uptime_seconds"].(float64); ok {
		out["uptime_s"] = v
	}
	// 前端取的是 upstream_healthy / upstream.ok，而 /readyz 给的是 upstream_ok。
	// 补一个同义字段，别让运维对着 "—" 猜。
	if ok, exists := out["upstream_ok"]; exists {
		out["upstream_healthy"] = ok
	}
	if url, ok := out["upstream"].(string); ok {
		out["upstream_url"] = url
	}

	// 内存：给出 used / peak / budget 三者（前端按 memory.* 取值）
	used, peak := heapUsage()
	budgetBytes := int64(0)
	if v, ok := out["budget_target_mib"].(float64); ok {
		budgetBytes = int64(v * 1024 * 1024)
	}
	out["memory"] = map[string]any{
		"used_bytes":   used,
		"peak_bytes":   peak,
		"budget_bytes": budgetBytes,
	}
	out["memory_used_bytes"] = used
	out["memory_peak_bytes"] = peak
	out["memory_budget_bytes"] = budgetBytes

	// 检测模式与降级
	out["mode"] = s.o.Config.Engine.Mode
	out["fail_mode"] = s.o.Config.Engine.FailMode
	out["degrade"] = s.o.Config.Engine.Degrade

	if s.o.EventSummary != nil {
		dp := s.o.EventSummary()
		out["dataplane"] = dp
		// 降级档位同时给顶层与 overload 对象，前端两种写法都能取到
		if lvl, ok := dp["degrade_level"]; ok {
			out["degrade_level"] = lvl
			// overload.level 必须是**数字**：控制台拿它做数值比较（0=正常）。
			// 给字符串会让它判成 null，于是正常状态被显示成"系统处于降级状态 L?"。
			out["overload"] = map[string]any{
				"level":      dp["degrade_level_num"],
				"level_name": lvl,
				"reason":     dp["degrade_reason"],
				"rejected":   dp["rejected_503"],
			}
		}
		if r, ok := dp["degrade_reason"]; ok {
			out["degrade_reason"] = r
		}
		if rj, ok := dp["rejected_503"]; ok {
			out["degrade_rejected"] = rj
		}
	}

	if s.o.Limiter != nil {
		st := s.o.Limiter.Stats()
		out["ratelimit"] = map[string]any{
			"keys": st.Keys, "banned": st.Banned,
			"allowed": st.Allowed, "denied": st.Denied,
			"evicted": st.Evicted, "bans_issued": st.BansIssued,
		}
	}

	if s.o.Events != nil {
		sum := s.o.Events.Summary()
		out["events"] = sum
		out["events_total"] = sum.Total
		out["blocked_total"] = sum.Blocked
		out["by_category"] = sum.ByCategory
		out["categories"] = s.o.Events.CategoriesSorted()
		out["top_ips"] = s.o.Events.TopIPs(10)
		out["top_paths"] = s.o.Events.TopPaths(10)
		out["top_rules"] = s.o.Events.TopRules(10)
	}

	if st := s.o.Control; st != nil {
		if snap := st.Snapshot(); snap != nil {
			out["config_version"] = snap.Version
			out["config_reason"] = snap.Reason
			out["config_since"] = snap.Since.Format(time.RFC3339)
			if snap.RuleSet != nil {
				rs := snap.RuleSet.Stats()
				out["ruleset"] = map[string]any{
					"version":         snap.RuleSet.Version,
					"rules":           rs.Rules,
					"count":           rs.Rules,
					"enabled":         rs.Enabled,
					"disabled":        rs.Disabled,
					"chains":          rs.Chains,
					"prefilter_nodes": rs.PrefilterNodes,
					"no_literal":      rs.NoLiteralRules,
					"loaded_at":       snap.RuleSet.LoadedAt.Format(time.RFC3339),
					"warnings":        rs.Warnings,
				}
				out["ruleset_version"] = snap.RuleSet.Version
				out["rule_count"] = rs.Rules
			}
			out["exceptions"] = len(snap.Exceptions)
			out["ip_lists"] = map[string]any{
				"allow": len(snap.IPLists.Allow),
				"deny":  len(snap.IPLists.Deny),
			}
		}
	}

	out["console"] = map[string]any{
		"sessions":     s.session.count(),
		"logins":       s.logins.Load(),
		"login_fails":  s.loginFails.Load(),
		"gate_fails":   s.gateFails.Load(),
		"csrf_rejects": s.csrfFails.Load(),
		"blocked":      s.blockedReqs.Load(),
	}
	writeJSON(w, http.StatusOK, out)
}

// heapUsage 返回堆在用与峰值字节数。
//
// 用 runtime/metrics 而不是 runtime.MemStats：后者要 stop-the-world，
// 控制台刷新频率可能不低，不该为了显示一个数字去停世界。
func heapUsage() (used, peak int64) {
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/unused:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
		{Name: "/memory/classes/heap/free:bytes"},
	}
	metrics.Read(samples)
	get := func(s metrics.Sample) int64 {
		if s.Value.Kind() == metrics.KindUint64 {
			return int64(s.Value.Uint64())
		}
		return 0
	}
	used = get(samples[0])
	// "峰值"这里用堆的保留量（objects+unused+released+free）近似：
	// 真正的历史峰值需要自己采样维护，控制台只要一个量级参考。
	peak = used + get(samples[1]) + get(samples[2]) + get(samples[3])
	return used, peak
}

func (s *Server) handleMetricsSummary(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	out := map[string]any{}
	if s.o.Events != nil {
		sum := s.o.Events.Summary()
		out["events"] = sum
		out["top_categories"] = s.o.Events.Categories()
		out["top_ips"] = s.o.Events.TopIPs(10)
	}
	if s.o.EventSummary != nil {
		out["dataplane"] = s.o.EventSummary()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleTimeseries(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	if s.o.Events == nil {
		writeJSON(w, http.StatusOK, map[string]any{"points": []any{}})
		return
	}
	minutes := 60
	switch strings.TrimSpace(r.URL.Query().Get("range")) {
	case "5m":
		minutes = 5
	case "15m":
		minutes = 15
	case "1h", "":
		minutes = 60
	case "6h":
		minutes = 360
	case "24h":
		minutes = 1440
	}
	// 上限来自配置：控制台不许做大范围扫描（2C2G 上先翻车的就是这里）
	if max := s.o.Config.Admin.Events.MaxQueryRange.D(); max > 0 {
		if lim := int(max.Minutes()); lim > 0 && minutes > lim {
			minutes = lim
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"points": s.o.Events.Timeseries(minutes),
		"range":  fmt.Sprintf("%dm", minutes),
	})
}

// ---------------------------------------------------------------- 事件

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	if s.o.Events == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []any{}, "next_cursor": ""})
		return
	}
	q := r.URL.Query()
	limit := queryInt(r, "limit", 50)
	if max := s.o.Config.Admin.Events.MaxRows; max > 0 && limit > max {
		limit = max
	}
	query := eventQueryFrom(q, limit)
	list, next := s.o.Events.List(query)
	writeJSON(w, http.StatusOK, map[string]any{
		"events":      list,
		"items":       list, // 兼容前端两种取值
		"next_cursor": next,
		"total":       s.o.Events.Total(),
		"retained":    s.o.Events.Len(),
	})
}

// handleEventByID 处理 /events/:id 与 /events/:id/raw。
func (s *Server) handleEventByID(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, s.mount+"/api/v1/events/")
	rest = strings.Trim(rest, "/")
	if rest == "" || s.o.Events == nil {
		s.writeError(w, http.StatusNotFound, "not_found", "事件不存在", "")
		return
	}

	id := rest
	raw := false
	if strings.HasSuffix(rest, "/raw") {
		id = strings.TrimSuffix(rest, "/raw")
		raw = true
	}
	e, ok := s.o.Events.Get(id)
	if !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "事件不存在（可能已被 ring buffer 淘汰）", "")
		return
	}
	if raw {
		// 取证用途：以纯文本返回"变换前 / 变换后"两块，**已可打印化**。
		// 前端用 renderCode 原语展示，绝不拼 HTML。
		var sb strings.Builder
		sb.WriteString("# request\n")
		fmt.Fprintf(&sb, "%s %s %s\n", e.Method, e.Path, e.Proto)
		fmt.Fprintf(&sb, "host: %s\nclient_ip: %s\ntx_id: %s\n", e.Host, e.ClientIP, e.TxID)
		if e.RuleID != "" {
			fmt.Fprintf(&sb, "rule: %s  category: %s  target: %s\n", e.RuleID, e.Category, e.Target)
		}
		if e.PayloadBefore != "" {
			sb.WriteString("\n# payload_before\n")
			sb.WriteString(e.PayloadBefore)
			sb.WriteString("\n")
		}
		if e.PayloadAfter != "" {
			sb.WriteString("\n# payload_after（变换后）\n")
			sb.WriteString(e.PayloadAfter)
			sb.WriteString("\n")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sb.String()))
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// ---------------------------------------------------------------- 规则

// ruleView 是规则的对外视图。
//
// 有意**不返回正则源码与样本**：控制台读接口可能被低权限查看，
// 而规则细节本身就是攻击者的情报。要看细节走"规则测试台"（有操作审计）。
type ruleView struct {
	ID         string   `json:"id"`
	Message    string   `json:"message"`
	Phase      string   `json:"phase"`
	Severity   string   `json:"severity"`
	Category   string   `json:"category"`
	Score      int      `json:"score"`
	Tags       []string `json:"tags,omitempty"`
	Enabled    bool     `json:"enabled"`
	Operator   string   `json:"operator"`
	Transforms []string `json:"transforms,omitempty"`
	Targets    []string `json:"targets"`
	Source     string   `json:"source"`
	HardBlock  bool     `json:"hard_block,omitempty"`
	Action     string   `json:"action,omitempty"`
	ChainHead  bool     `json:"chain_head,omitempty"`
	// DisabledByConsole 区分"文件里就禁用"与"控制台临时停用"。
	DisabledByConsole bool `json:"disabled_by_console,omitempty"`
}

func (s *Server) rulesView() ([]ruleView, *rules.RuleSet, *control.State) {
	snap := s.o.Control.Snapshot()
	if snap == nil || snap.RuleSet == nil {
		return nil, nil, snap
	}
	rs := snap.RuleSet
	all := rs.Rules()
	out := make([]ruleView, 0, len(all))
	for _, r := range all {
		targets := make([]string, 0, len(r.Targets))
		for _, t := range r.Targets {
			label := t.Collection
			if t.Selector != "" {
				label += ":" + t.Selector
			} else if t.SelectorRe != nil {
				label += ":<regex>"
			}
			targets = append(targets, label)
		}
		out = append(out, ruleView{
			ID: r.ID, Message: r.Message, Phase: r.Phase.String(), Severity: r.Severity.String(),
			Category: r.Category, Score: r.Score, Tags: r.Tags, Enabled: r.Enabled,
			Operator: r.OperatorName, Transforms: r.TransformNames, Targets: targets,
			Source: r.Source.String(), HardBlock: r.HardBlock, Action: r.Action.Type,
			ChainHead:         len(r.ChainMembers) > 1,
			DisabledByConsole: snap.DisabledRules[r.ID],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, rs, snap
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	list, rs, snap := s.rulesView()
	if rs == nil {
		writeJSON(w, http.StatusOK, map[string]any{"rules": []any{}, "version": ""})
		return
	}
	st := rs.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":   list,
		"version": rs.Version,
		"snapshot": func() string {
			if snap != nil {
				return snap.Version
			}
			return ""
		}(),
		"stats": map[string]any{
			"total": st.Rules, "enabled": st.Enabled, "disabled": st.Disabled,
			"chains": st.Chains, "prefilter_nodes": st.PrefilterNodes,
			"literal_rules": st.LiteralRules, "no_literal_rules": st.NoLiteralRules,
			"by_category": st.ByCategory, "warnings": st.Warnings,
		},
	})
}

// handleRuleByID 支持 GET 详情与 PATCH 启停。
func (s *Server) handleRuleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, s.mount+"/api/v1/rules/"), "/")
	if id == "" {
		s.writeError(w, http.StatusNotFound, "not_found", "缺少规则 ID", "")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !s.requireRead(w, r) {
			return
		}
		list, rs, _ := s.rulesView()
		if rs == nil {
			s.writeError(w, http.StatusServiceUnavailable, "no_ruleset", "规则集尚未加载", "")
			return
		}
		for _, v := range list {
			if v.ID == id {
				if tr, err := rs.TraceValue(id, "sample-value"); err == nil {
					// 只回结构信息，不回样本与正则
					_ = tr
				}
				writeJSON(w, http.StatusOK, v)
				return
			}
		}
		s.writeError(w, http.StatusNotFound, "not_found", "规则不存在", "")

	case http.MethodPatch:
		if !s.requireWrite(w, r) {
			return
		}
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
			return
		}
		if req.Enabled == nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "缺少 enabled 字段", "")
			return
		}
		sess, _ := s.currentSession(r)
		mut := control.SetRuleEnabled{
			ID: id, Enabled: *req.Enabled, Dir: s.o.Config.Rules.Dir, Files: s.o.Config.Rules.Files,
		}
		_, warnings, err := s.o.Control.Apply(mut, actorOf(sess, r), s.clientIP(r))
		if err != nil {
			s.writeError(w, http.StatusUnprocessableEntity, "rule_toggle_failed", "规则集重载失败，已回滚", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(), Warnings: warnings})

	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只支持 GET / PATCH", "")
	}
}

// handleRulesValidate 校验一段规则 YAML（不落盘、不生效）。
func (s *Server) handleRulesValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	var req struct {
		YAML string `json:"yaml"`
		Name string `json:"name"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
		return
	}
	if strings.TrimSpace(req.YAML) == "" {
		s.writeError(w, http.StatusBadRequest, "bad_request", "yaml 不能为空", "")
		return
	}
	name := req.Name
	if name == "" {
		name = "console-validate.yaml"
	}
	opts := rules.DefaultOptions()
	opts.FileBase = s.o.Config.Rules.Dir
	rs, err := rules.LoadSource(opts, name, []byte(req.YAML))
	if err != nil {
		// 校验失败是**正常业务流**，用 200 + ok:false 更利于前端展示错误列表；
		// 这里给 422 让 CLI 也能靠状态码判断。
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": map[string]any{
				"code": "invalid_rules", "message": "规则校验未通过", "detail": err.Error(),
			},
		})
		return
	}
	st := rs.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "version": rs.Version,
		"stats": map[string]any{
			"rules": st.Rules, "enabled": st.Enabled, "chains": st.Chains,
			"literal_rules": st.LiteralRules, "no_literal_rules": st.NoLiteralRules,
			"warnings": st.Warnings,
		},
	})
}

// handleRulesTest 规则测试台：跑一个值，返回变换前后与判定结果。
func (s *Server) handleRulesTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	var req struct {
		RuleID string `json:"rule_id"`
		Value  string `json:"value"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
		return
	}
	snap := s.o.Control.Snapshot()
	if snap == nil || snap.RuleSet == nil {
		s.writeError(w, http.StatusServiceUnavailable, "no_ruleset", "规则集尚未加载", "")
		return
	}
	if strings.TrimSpace(req.RuleID) == "" {
		s.writeError(w, http.StatusBadRequest, "bad_request", "缺少 rule_id", "")
		return
	}
	tr, err := snap.RuleSet.TraceValue(req.RuleID, req.Value)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "rule_not_found", "规则测试失败", err.Error())
		return
	}
	sess, _ := s.currentSession(r)
	recordAuth(authEvent{Actor: actorOf(sess, r), Action: "rule_test", OK: true,
		Remote: s.clientIP(r), Detail: req.RuleID})
	writeJSON(w, http.StatusOK, map[string]any{
		"rule_id": tr.RuleID, "message": tr.Message, "phase": tr.Phase,
		"severity": tr.Severity, "category": tr.Category, "score": tr.Score,
		"operator": tr.Operator, "transforms": tr.Transforms,
		"before": tr.Before, "after": tr.After,
		"matched": tr.Matched, "detail": tr.Detail,
	})
}

// handleRulesReload 从磁盘重载规则集。
func (s *Server) handleRulesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	sess, _ := s.currentSession(r)
	mut := control.ReloadRules{Dir: s.o.Config.Rules.Dir, Files: s.o.Config.Rules.Files}
	_, warnings, err := s.o.Control.Apply(mut, actorOf(sess, r), s.clientIP(r))
	if err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "reload_failed",
			"规则重载失败，已保留原规则集（自测不过会整批拒绝）", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(), Warnings: warnings})
}

// ---------------------------------------------------------------- 拦截页

// handleBlockPage 读取或替换拦截页模板。
//
// 这是"拦截页内容可以在控制台自定义"的落点：
//
//	GET  → 当前模板、参数、以及是否在用自定义模板
//	PUT  → 替换模板（编译失败整次拒绝，旧模板继续生效）
func (s *Server) handleBlockPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireRead(w, r) {
			return
		}
		snap := s.o.Control.Snapshot()
		if snap == nil {
			s.writeError(w, http.StatusServiceUnavailable, "no_snapshot", "控制面尚未初始化", "")
			return
		}
		bp := snap.BlockPage
		writeJSON(w, http.StatusOK, map[string]any{
			"custom":        bp.CustomHTML != "",
			"html":          bp.CustomHTML,
			"file":          bp.File,
			"status":        bp.Options.Status,
			"branding":      bp.Options.Branding,
			"product_name":  bp.Options.ProductName,
			"product_url":   bp.Options.ProductURL,
			"contact":       bp.Options.Contact,
			"title":         bp.Options.Title,
			"version":       bp.Options.Version,
			"compile_error": bpRendererError(bp),
			"builtin":       builtin(),
			"variables":     blockPageVariables(),
			"snapshot":      snap.Version,
		})

	case http.MethodPut:
		if !s.requireWrite(w, r) {
			return
		}
		var req struct {
			HTML string `json:"html"`
			// 空字符串 = 恢复内置模板
			Reset *bool `json:"reset"`
			// 是否落盘（写进 block_page.file）
			Persist bool `json:"persist"`
			// 可选：一并调整参数
			Status      *int    `json:"status"`
			Branding    *bool   `json:"branding"`
			ProductName *string `json:"product_name"`
			ProductURL  *string `json:"product_url"`
			Contact     *string `json:"contact"`
			Title       *string `json:"title"`
		}
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
			return
		}
		html := req.HTML
		if req.Reset != nil && *req.Reset {
			html = ""
		}

		sess, _ := s.currentSession(r)
		actor := actorOf(sess, r)

		var warnings []string
		// 先改参数（如果有），再改模板 —— 两步都是"失败即整次拒绝"。
		if req.Status != nil || req.Branding != nil || req.ProductName != nil ||
			req.ProductURL != nil || req.Contact != nil || req.Title != nil {
			mut := control.SetBlockPageOptions{
				Status: derefInt(req.Status), Branding: req.Branding,
				ProductName: derefStr(req.ProductName), ProductURL: derefStr(req.ProductURL),
				Contact: derefStr(req.Contact), Title: derefStr(req.Title),
			}
			_, w2, err := s.o.Control.Apply(mut, actor, s.clientIP(r))
			if err != nil {
				s.writeError(w, http.StatusUnprocessableEntity, "invalid_options", "拦截页参数不合法，已回滚", err.Error())
				return
			}
			warnings = append(warnings, w2...)
		}

		file := ""
		if req.Persist {
			file = s.blockPageFilePath()
		}
		mut := control.SetBlockPageHTML{HTML: html, File: file, WriteFile: req.Persist}
		_, w3, err := s.o.Control.Apply(mut, actor, s.clientIP(r))
		if err != nil {
			s.writeError(w, http.StatusUnprocessableEntity, "invalid_template",
				"模板编译失败，已保留原模板", err.Error())
			return
		}
		warnings = append(warnings, w3...)
		writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(), Warnings: warnings})

	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只支持 GET / PUT", "")
	}
}

// handleBlockPagePreview 渲染预览（**不产生状态变更**）。
func (s *Server) handleBlockPagePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	var req struct {
		HTML     string `json:"html"`
		Method   string `json:"method"`
		Host     string `json:"host"`
		Path     string `json:"path"`
		Category string `json:"category"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
		return
	}
	snap := s.o.Control.Snapshot()
	if snap == nil {
		s.writeError(w, http.StatusServiceUnavailable, "no_snapshot", "控制面尚未初始化", "")
		return
	}
	html, err := control.PreviewBlockPageHTML(snap, req.HTML, control.SampleRequest{
		Method: req.Method, Host: req.Host, Path: req.Path, Category: req.Category,
	})
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": map[string]any{
				"code": "invalid_template", "message": "模板编译失败", "detail": err.Error(),
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "html": html})
}

func (s *Server) blockPageFilePath() string {
	f := strings.TrimSpace(s.o.Config.BlockPage.File)
	if f == "" {
		return ""
	}
	if filepath.IsAbs(f) {
		return f
	}
	if s.o.Config.Path != "" {
		return filepath.Join(filepath.Dir(s.o.Config.Path), f)
	}
	return f
}

func bpRendererError(bp control.BlockPageState) string {
	if bp.Renderer == nil {
		return ""
	}
	return bp.Renderer.CustomError()
}

// builtin 返回内置模板（控制台里"恢复默认"要能看到它）。
func builtin() string { return blockpage.BuiltinTemplate() }

// ---------------------------------------------------------------- 限速与封禁

func (s *Server) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireRead(w, r) {
			return
		}
		snap := s.o.Control.Snapshot()
		out := map[string]any{}
		if snap != nil {
			out = map[string]any{
				"enabled":        snap.RateLimit.Enabled,
				"rps":            snap.RateLimit.RPS,
				"burst":          snap.RateLimit.Burst,
				"ban_after_hits": snap.RateLimit.BanAfterHits,
				// 可读形式与秒数都给：控制台按秒数格式化，
				// 只给 "2m0s" 这种字符串它会显示成 "—"。
				"ban_window":     snap.RateLimit.BanWindow.String(),
				"ban_window_s":   int(snap.RateLimit.BanWindow.Seconds()),
				"ban_duration":   snap.RateLimit.BanDuration.String(),
				"ban_duration_s": int(snap.RateLimit.BanDuration.Seconds()),
				"whitelist":      snap.RateLimit.Whitelist,
			}
		}
		if s.o.Limiter != nil {
			st := s.o.Limiter.Stats()
			out["stats"] = map[string]any{
				"keys": st.Keys, "banned": st.Banned, "allowed": st.Allowed,
				"denied": st.Denied, "evicted": st.Evicted, "bans_issued": st.BansIssued,
			}
		}
		writeJSON(w, http.StatusOK, out)

	case http.MethodPut:
		if !s.requireWrite(w, r) {
			return
		}
		var req struct {
			Enabled      *bool     `json:"enabled"`
			RPS          *float64  `json:"rps"`
			Burst        *float64  `json:"burst"`
			BanAfterHits *int      `json:"ban_after_hits"`
			BanWindow    *string   `json:"ban_window"`
			BanDuration  *string   `json:"ban_duration"`
			Whitelist    *[]string `json:"whitelist"`
		}
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
			return
		}
		mut := control.SetRateLimit{Enabled: req.Enabled, RPS: req.RPS, Burst: req.Burst, BanAfterHits: req.BanAfterHits}
		if req.BanWindow != nil {
			d, err := time.ParseDuration(*req.BanWindow)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, "bad_request", "ban_window 解析失败", err.Error())
				return
			}
			mut.BanWindow = &d
		}
		if req.BanDuration != nil {
			d, err := time.ParseDuration(*req.BanDuration)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, "bad_request", "ban_duration 解析失败", err.Error())
				return
			}
			mut.BanDuration = &d
		}
		if req.Whitelist != nil {
			mut.Whitelist = *req.Whitelist
		}
		sess, _ := s.currentSession(r)
		_, warnings, err := s.o.Control.Apply(mut, actorOf(sess, r), s.clientIP(r))
		if err != nil {
			s.writeError(w, http.StatusUnprocessableEntity, "invalid_ratelimit", "限速参数不合法，已回滚", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(), Warnings: warnings})

	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只支持 GET / PUT", "")
	}
}

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	if s.o.Limiter == nil {
		writeJSON(w, http.StatusOK, map[string]any{"bans": []any{}})
		return
	}
	limit := queryInt(r, "limit", 100)
	writeJSON(w, http.StatusOK, map[string]any{
		"bans":  s.o.Limiter.BannedList(limit),
		"stats": s.o.Limiter.Stats(),
	})
}

// handleBanByIP 处理 DELETE /bans/:ip（解封）。
func (s *Server) handleBanByIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只支持 DELETE", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	ip := strings.Trim(strings.TrimPrefix(r.URL.Path, s.mount+"/api/v1/bans/"), "/")
	if ip == "" {
		s.writeError(w, http.StatusBadRequest, "bad_request", "缺少 IP", "")
		return
	}
	if s.o.Limiter == nil {
		s.writeError(w, http.StatusServiceUnavailable, "ratelimit_disabled", "限速未启用", "")
		return
	}
	s.o.Limiter.Unban(ip)
	sess, _ := s.currentSession(r)
	recordAuth(authEvent{Actor: actorOf(sess, r), Action: "unban", OK: true,
		Remote: s.clientIP(r), Detail: ip})
	writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion()})
}

// ---------------------------------------------------------------- 配置与审计

// handleConfig 返回当前配置（**脱敏**）。
//
// 绝不返回 password_hash / api_token / gate.password_hash ——
// 控制台读接口可能被低权限查看，凭据哈希也不该出现在浏览器里。
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	// PUT 直接拒绝并指路：通用配置写入会静默忽略"改不了"的字段，
	// 运维以为改生效了、实际要重启 —— 这种接口比没有更糟。
	if r.Method == http.MethodPut || r.Method == http.MethodPatch {
		if !s.requireWrite(w, r) {
			return
		}
		s.handleConfigPut(w, r)
		return
	}
	if !s.requireRead(w, r) {
		return
	}
	snap := s.o.Control.Snapshot()
	out := map[string]any{
		"profile":        s.o.Config.ResolvedProfile,
		"profile_source": s.o.Config.ProfileSource,
		"listen":         s.o.Config.Listen.Addr,
		"upstream":       s.o.Config.Upstream.URL,
		"engine": map[string]any{
			"mode": s.o.Config.Engine.Mode, "fail_mode": s.o.Config.Engine.FailMode,
			"degrade":                   s.o.Config.Engine.Degrade,
			"inbound_anomaly_threshold": s.o.Config.Engine.InboundAnomalyThreshold,
		},
		"rules": map[string]any{
			"dir": s.o.Config.Rules.Dir, "files": s.o.Config.Rules.Files,
			"self_test": s.o.Config.Rules.SelfTest,
		},
		"real_ip": map[string]any{
			"header":          s.o.Config.RealIP.Header,
			"trusted_proxies": s.o.Config.RealIP.TrustedProxies,
		},
		"block_page": map[string]any{
			"status": s.o.Config.BlockPage.Status, "branding": s.o.Config.BlockPage.BrandingOn(),
			"file": s.o.Config.BlockPage.File,
		},
		"admin": map[string]any{
			"enabled": s.o.Config.Admin.Enabled, "addr": s.o.Config.Admin.Addr,
			"gate_enabled":  s.o.Config.Admin.Gate.Enabled,
			"gate_mode":     s.o.Config.Admin.Gate.Mode,
			"auth_mode":     s.o.Config.Admin.AuthMode,
			"username":      s.o.Config.Admin.Username,
			"tls_enabled":   s.o.Config.Admin.TLS.Enabled,
			"password_hash": "***（已脱敏）",
			"api_token":     redactSecret(s.o.Config.Admin.APIToken),
		},
	}
	if snap != nil {
		out["snapshot"] = snap.Version
		out["snapshot_reason"] = snap.Reason
		out["snapshot_since"] = snap.Since.Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, out)
}

func redactSecret(s string) string {
	if s == "" {
		return ""
	}
	return "***（已设置）"
}

// handleConsoleAudit 返回控制台操作审计（变更 + 登录）。
func (s *Server) handleConsoleAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	limit := queryInt(r, "limit", 100)
	changes := s.o.Control.Ops(limit)
	auth := authEvents(limit)

	// 控制台读的是 audit / items / data / records 之一，并且期望每行有
	// actor/action/at/ok 这些统一字段。这里把"配置变更"与"登录等认证事件"
	// 合并成一个按时间倒序的列表 —— 运维想看的是"这个控制台被人动过什么"，
	// 而不是分成两张表自己去对。
	type auditRow struct {
		At          time.Time `json:"at"`
		Actor       string    `json:"actor"`
		Action      string    `json:"action"`
		Target      string    `json:"target,omitempty"`
		OK          bool      `json:"ok"`
		Remote      string    `json:"remote,omitempty"`
		Detail      string    `json:"detail,omitempty"`
		Error       string    `json:"error,omitempty"`
		FromVersion string    `json:"from_version,omitempty"`
		ToVersion   string    `json:"to_version,omitempty"`
		Warnings    []string  `json:"warnings,omitempty"`
		Kind        string    `json:"kind"`
	}
	rows := make([]auditRow, 0, len(changes)+len(auth))
	for _, c := range changes {
		rows = append(rows, auditRow{
			At: c.At, Actor: c.Actor, Action: c.Action, OK: c.OK, Remote: c.Remote,
			Detail: c.Detail, Error: c.Error, FromVersion: c.From, ToVersion: c.To,
			Warnings: c.Warnings, Kind: "change",
		})
	}
	for _, a := range auth {
		rows = append(rows, auditRow{
			At: a.At, Actor: a.Actor, Action: a.Action, OK: a.OK, Remote: a.Remote,
			Detail: a.Detail, Kind: "auth",
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].At.After(rows[j].At) })
	if len(rows) > limit {
		rows = rows[:limit]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":   rows,
		"audit":   rows,
		"changes": changes,
		"auth":    auth,
	})
}

// ---------------------------------------------------------------- 内部工具

func (s *Server) cookiePath() string {
	if s.mount != "" {
		return s.mount
	}
	return "/"
}

func (s *Server) snapshotVersion() string {
	if snap := s.o.Control.Snapshot(); snap != nil {
		return snap.Version
	}
	return ""
}

func actorOf(sess *session, r *http.Request) string {
	if sess != nil {
		return sess.User
	}
	if strings.TrimSpace(r.Header.Get(tokenHeader)) != "" {
		return "api-token"
	}
	return "unknown"
}

// currentSession 取当前会话（cookie 或 API token 都算已认证）。
func (s *Server) currentSession(r *http.Request) (*session, bool) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		if sess, ok := s.session.get(c.Value); ok {
			idle := s.o.Config.Admin.SessionIdleTimeout.D()
			if idle <= 0 {
				idle = 2 * time.Hour
			}
			s.session.touch(c.Value, idle)
			return sess, true
		}
	}
	if s.tokenValid(r) {
		// API token 视作一个特殊会话（CLI 用）
		return &session{User: "api-token", CSRF: "token"}, true
	}
	return nil, false
}

// requireRead 守卫读接口。
func (s *Server) requireRead(w http.ResponseWriter, r *http.Request) bool {
	if _, ok := s.currentSession(r); !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "需要先登录", "")
		return false
	}
	return true
}

// requireWrite 守卫写接口：会话 + CSRF + 自定义头 + Origin，四道都要过。
//
// 为什么写操作不能只靠会话 cookie：浏览器会**自动附带** cookie，
// 一个跨站表单就能借管理员的手改配置。所以必须叠加只有同源 JS 才能加上的东西。
func (s *Server) requireWrite(w http.ResponseWriter, r *http.Request) bool {
	sess, ok := s.currentSession(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthenticated", "需要先登录", "")
		return false
	}
	// API token 走的 CLI 路径：没有浏览器上下文，跳过 CSRF，但仍要求自定义头。
	if sess.User == "api-token" {
		if r.Header.Get(consoleHeader) == "" {
			s.writeError(w, http.StatusForbidden, "missing_console_header",
				"写操作必须带 "+consoleHeader+" 头", "")
			return false
		}
		return true
	}

	if r.Header.Get(consoleHeader) == "" {
		s.csrfFails.Add(1)
		s.writeError(w, http.StatusForbidden, "missing_console_header",
			"写操作必须带 "+consoleHeader+" 头", "")
		return false
	}
	if err := checkOrigin(r); err != nil {
		s.csrfFails.Add(1)
		s.writeError(w, http.StatusForbidden, "bad_origin", "来源校验未通过", err.Error())
		return false
	}
	// 先看请求头有没有带 —— 缺头与不匹配是两种不同的故障，诊断信息要分得开
	hdr := r.Header.Get(csrfHeader)
	if hdr == "" {
		s.csrfFails.Add(1)
		s.writeError(w, http.StatusForbidden, "missing_csrf", "缺少 CSRF 令牌请求头", "")
		return false
	}
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" {
		s.csrfFails.Add(1)
		s.writeError(w, http.StatusForbidden, "missing_csrf", "缺少 CSRF 令牌 Cookie", "")
		return false
	}
	token, ok := checkCSRFSig(s.secret, c.Value)
	if !ok {
		s.csrfFails.Add(1)
		s.writeError(w, http.StatusForbidden, "bad_csrf", "CSRF 令牌签名无效", "")
		return false
	}
	if hdr != sess.CSRF || hdr != token {
		s.csrfFails.Add(1)
		s.writeError(w, http.StatusForbidden, "csrf_mismatch", "CSRF 令牌不匹配", "")
		return false
	}
	return true
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// blockPageVariables 列出模板里可用的变量，供控制台提示。
//
// **这份清单必须与 blockpage.Data 的字段保持一致** ——
// 它是运维写模板时的"字典"，写错了会让人白折腾半天。
func blockPageVariables() []map[string]string {
	return []map[string]string{
		{"name": "Status", "desc": "状态码，如 403"},
		{"name": "StatusText", "desc": "状态码文本，如 Forbidden"},
		{"name": "Title", "desc": "页面标题"},
		{"name": "Category", "desc": "机器可读的命中类目，如 sqli"},
		{"name": "CategoryLabel", "desc": "类目的中文名，如 SQL 注入"},
		{"name": "TxID", "desc": "请求 ID（用户报障时提供这个）"},
		{"name": "Time", "desc": "拦截时间"},
		{"name": "Method", "desc": "请求方法"},
		{"name": "Host", "desc": "站点（Host 头，已转义）"},
		{"name": "Path", "desc": "规范化后的路径（已转义）"},
		{"name": "ClientIP", "desc": "客户端 IP"},
		{"name": "RetryAfter", "desc": "建议等待秒数（限速/封禁时）"},
		{"name": "ProductName", "desc": "产品名（branding 开启时展示）"},
		{"name": "ProductURL", "desc": "产品主页"},
		{"name": "Contact", "desc": "误报申诉渠道"},
		{"name": "Version", "desc": "构建版本"},
		{"name": "Branding", "desc": "是否展示品牌（true/false）"},
	}
}

// eventQueryFrom 把查询参数翻译成事件查询条件。
//
// 抽出来是让 /events 与 /events/export 用**同一套**过滤语义 ——
// 两边各写一遍，导出出来的东西迟早和页面上看到的不是一回事。
func eventQueryFrom(q url.Values, limit int) eventstore.Query {
	query := eventstore.Query{
		Cursor:       q.Get("cursor"),
		Limit:        limit,
		Verdict:      q.Get("verdict"),
		Category:     q.Get("category"),
		Severity:     q.Get("severity"),
		ClientIP:     q.Get("client_ip"),
		RuleID:       q.Get("rule_id"),
		PathContains: q.Get("path"),
		Search:       q.Get("q"),
		OnlyBlocked:  q.Get("blocked") == "1" || q.Get("blocked") == "true",
	}
	if v := q.Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			query.Since = t
		}
	}
	if v := q.Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			query.Until = t
		}
	}
	return query
}

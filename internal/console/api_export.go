package console

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 本文件补齐前端还需要、但之前没实现的端点：
// 事件导出、规则集列表、门槛状态与轮换、配置校验与重载。
//
// 一条纪律：**能预览的都要能预览**（配置 diff 走 Preview，不产生状态变更）。

// ---------------------------------------------------------------- 事件导出

// handleEventsExport 导出事件。
//
// 两种格式：
//
//	?format=jsonl（默认） 每行一条 JSON，便于喂给 jq / SIEM
//	?format=csv          表头 + 若干列，便于丢进表格
//
// 只导出内存 ring 里的（受 ring 容量限制）—— 全量历史在按天落盘的审计日志里，
// 控制台不做"翻全量"，那是 2C2G 上最先翻车的地方。
func (s *Server) handleEventsExport(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	if s.o.Events == nil {
		s.writeError(w, http.StatusServiceUnavailable, "events_disabled", "事件存储未启用", "")
		return
	}
	q := r.URL.Query()
	limit := queryInt(r, "limit", 1000)
	if max := s.o.Config.Admin.Events.MaxRows; max > 0 && limit > max*5 {
		limit = max * 5
	}
	query := eventQueryFrom(q, limit)
	list, _ := s.o.Events.List(query)

	format := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if format == "" {
		format = "jsonl"
	}
	stamp := time.Now().Format("20060102-150405")

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="donothack-events-%s.csv"`, stamp))
		w.Header().Set("Cache-Control", "no-store")
		// 加 BOM：Excel 打开 UTF-8 CSV 不带 BOM 会乱码（中文列名尤其明显）
		_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"时间", "请求ID", "来源IP", "方法", "路径", "裁决", "分数",
			"规则", "类目", "严重度", "目标", "明细", "状态码"})
		for _, e := range list {
			// 每个字段都过一遍 csvCell：
			// 路径/UA/明细里很可能出现 `=cmd|...`、`+`、`-`、`@` 开头的值，
			// 而 Excel/Sheets 会把它们当**公式**执行 —— 那是"导出一份日志
			// 反而把自己打穿"的经典路径。
			_ = cw.Write([]string{
				csvCell(e.Ts.Format(time.RFC3339)), csvCell(e.TxID), csvCell(e.ClientIP),
				csvCell(e.Method), csvCell(e.Path), csvCell(e.Verdict),
				strconv.Itoa(e.Score), csvCell(e.RuleID), csvCell(e.Category),
				csvCell(e.Severity), csvCell(e.Target), csvCell(e.Detail),
				strconv.Itoa(e.Status),
			})
		}
		cw.Flush()
		return

	default:
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="donothack-events-%s.jsonl"`, stamp))
		w.Header().Set("Cache-Control", "no-store")
		for _, e := range list {
			_, _ = w.Write([]byte(eventJSON(e)))
			_, _ = w.Write([]byte("\n"))
		}
		return
	}
}

// ---------------------------------------------------------------- 规则集列表

// csvCell 中和 CSV 里的公式注入。
//
// Excel / Google Sheets 会把 `=`、`+`、`-`、`@` 以及制表符/回车开头的单元格
// **当公式执行**。而我们的导出列里有路径、UA、明细 —— 这些都是攻击者可控的，
// 于是"运维导出一份日志用 Excel 打开"就变成了一条打穿运维机器的路径
// （DDE、外链加载那一类）。
//
// 做法是业界通行的：在前面加一个单引号。Excel 会把它当成"文本"，
// 而 CSV 消费方（脚本）看到的就是原值前面多一个引号 —— 对日志分析无害。
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// handleRuleSets 返回当前加载的规则集信息。
//
// 目前只有一份"活着的"快照（热重载是原子替换，不保留历史版本）；
// 前端拿它显示版本、条数、加载时间与告警。
func (s *Server) handleRuleSets(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	snap := s.o.Control.Snapshot()
	items := []map[string]any{}
	if snap != nil && snap.RuleSet != nil {
		st := snap.RuleSet.Stats()
		items = append(items, map[string]any{
			"version":          snap.RuleSet.Version,
			"loaded_at":        snap.RuleSet.LoadedAt.Format(time.RFC3339),
			"source":           snap.RuleSet.Source,
			"rules":            st.Rules,
			"enabled":          st.Enabled,
			"disabled":         st.Disabled,
			"chains":           st.Chains,
			"literal_rules":    st.LiteralRules,
			"no_literal_rules": st.NoLiteralRules,
			"prefilter_nodes":  st.PrefilterNodes,
			"by_category":      st.ByCategory,
			"warnings":         st.Warnings,
			"active":           true,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rulesets": items,
		"items":    items,
		"note":     "热重载是原子替换，不保留历史版本；要回滚请把备份里的规则文件写回后重载。",
	})
}

// ---------------------------------------------------------------- 门槛

// handleGate 返回门槛状态（**绝不返回明文凭据**）。
func (s *Server) handleGate(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	cfg := s.o.Config.Admin.Gate
	out := map[string]any{
		"enabled":  cfg.Enabled,
		"mode":     cfg.Mode,
		"realm":    cfg.Realm,
		"username": cfg.Username,
		// 明文一律不回；只说明"配没配"
		"credential_configured": strings.TrimSpace(s.gate.get()) != "",
		"path_token_set":        cfg.PathToken != "",
		"tls_enabled":           s.o.Config.Admin.TLS.Enabled,
		"probe_ban_after":       cfg.ProbeBanAfter,
		"probe_ban_window_s":    int(cfg.ProbeBanWindow.D().Seconds()),
		"probe_ban_duration_s":  int(cfg.ProbeBanDuration.D().Seconds()),
		"gate_failures":         s.gateFails.Load(),
		"tls_self_signed": s.o.Config.Admin.TLS.AutoSelfSigned &&
			strings.TrimSpace(s.o.Config.Admin.TLS.CertFile) == "",
	}
	if out["realm"] == "" {
		out["realm"] = defaultRealm
	}
	// 把两道封禁的**实际运行数据**暴露出来（-02 的另一半：
	// 阈值生效了还不够，运维得能看见"现在封了几个、拒了多少次"，
	// 否则出问题只剩"怎么突然登录不上了"）。
	pBanned, pRejected, pEvicted, pOK, pTracked := s.probeThrottle.stats()
	lBanned, lRejected, lEvicted, lOK, lTracked := s.loginThrottle.stats()
	out["throttle"] = map[string]any{
		"probe": map[string]any{
			"tracked": pTracked, "bans": pBanned, "rejected": pRejected,
			"evicted": pEvicted, "successes": pOK,
			"max_fails": s.probeThrottle.max,
			"window_s":  int(s.probeThrottle.window.Seconds()),
			"lockout_s": int(s.probeThrottle.lockout.Seconds()),
		},
		"login": map[string]any{
			"tracked": lTracked, "bans": lBanned, "rejected": lRejected,
			"evicted": lEvicted, "successes": lOK,
			"max_fails": s.loginThrottle.max,
			"window_s":  int(s.loginThrottle.window.Seconds()),
			"lockout_s": int(s.loginThrottle.lockout.Seconds()),
		},
	}
	writeJSON(w, http.StatusOK, out)
}

// handleGateRotate 轮换门槛凭据。
//
// 返回**一次**新口令：这是它唯一一次出现在响应里，服务端只保存哈希。
// 与登录口令分开轮换是这套设计的意义所在 —— 门槛凭据可以交给运维同事，
// 泄露了单独换掉，不影响真正的登录账号。
func (s *Server) handleGateRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	pw, err := generatePassword()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "generate_failed", "生成口令失败", err.Error())
		return
	}
	hash, err := hashPassword(pw)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "hash_failed", "生成哈希失败", err.Error())
		return
	}
	s.gate.set(hash)
	sess, _ := s.currentSession(r)
	recordAuth(authEvent{Actor: actorOf(sess, r), Action: "gate_rotate", OK: true, Remote: s.clientIP(r)})

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"warning": "这个口令只显示这一次，服务端只存哈希；请立刻保存。" +
			"它只作用于当前进程 —— 要持久化请把新哈希写进 admin.gate.password_hash。",
		"username": s.o.Config.Admin.Gate.Username,
		"password": pw,
	})
}

// handleGateCertSelfSigned 报告自签证书的生成方式（证书只在内存里，无法导出）。
func (s *Server) handleGateCertSelfSigned(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	if !s.o.Config.Admin.TLS.Enabled {
		s.writeError(w, http.StatusUnprocessableEntity, "tls_disabled",
			"控制台 TLS 未启用，无需证书", "把 admin.tls.enabled 设为 true 才会生成/加载证书")
		return
	}
	if strings.TrimSpace(s.o.Config.Admin.TLS.CertFile) != "" {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "mode": "configured",
			"detail": "当前使用配置里指定的证书：" + s.o.Config.Admin.TLS.CertFile +
				"；重新生成请替换证书文件后重启。",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "mode": "auto_self_signed",
		"detail": "当前使用自动生成的自签证书（SAN 含主机名与本机 IP），**只存在于内存**，" +
			"每次启动重新生成。这样避免把私钥落到磁盘上多出一份需要保护的文件。" +
			"要固定证书请配置 admin.tls.cert_file / key_file。",
	})
}

// ---------------------------------------------------------------- TOTP

// handleTOTPEnroll 生成（或重新生成）TOTP 密钥。
//
// 语义取舍：**带 code 就校验后激活，不带就"先生成、暂不激活"**。
// 为什么不直接激活：认证器里填错一位就会把管理员锁在外面 ——
// 而"锁在外面"这种故障，代价远高于"少点一次确认"。
// 前端目前只调不带 code 的形式，因此状态会显示"未启用（待确认）"，这是**如实**的。
func (s *Server) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	var req struct {
		Code string `json:"code"`
		// Password 仅在"已启用两步验证、要换绑"时必须提供（见下面的说明）。
		Password string `json:"password"`
		// CurrentCode 也可以用当前生效的验证码代替口令。
		CurrentCode string `json:"current_code"`
	}
	// 允许空体：前端就是空对象调用
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
			return
		}
	}

	issuer := "donothack"
	account := s.o.Config.Admin.Username
	if account == "" {
		account = "admin"
	}
	sess, _ := s.currentSession(r)

	// ---- 带验证码 = 确认激活 ----
	//
	// **必须用"上一次生成并暂存的那把密钥"来校验**，不能在这里再生成一把：
	// 客户端手里的验证码来自上一次 enroll 返回的密钥，若这里重新生成，
	// 就变成"拿新密钥校验旧验证码" —— 结果是**永远激活不了**。
	// （这是真踩到的：端到端脚本连着调两次，第二次必然 422。）
	if code := strings.TrimSpace(req.Code); code != "" {
		pending := strings.TrimSpace(s.totpPending.get())
		if pending == "" {
			s.writeError(w, http.StatusPreconditionFailed, "no_pending_secret",
				"还没有待确认的密钥", "请先不带 code 调用一次本接口生成密钥")
			return
		}
		// **换绑必须再过一道身份**：
		// 只有会话是不够的 —— 会话泄露不该等于"能换掉或关掉第二因子"。
		// 已启用时要求：当前生效验证码，或登录口令。
		if s.totpEnabled() {
			active := strings.TrimSpace(s.totp.get())
			okCurrent := active != "" && verifyTOTP(active, req.CurrentCode, time.Now())
			okPassword := verifyPassword(s.login.get(), req.Password)
			if !okCurrent && !okPassword {
				recordAuth(authEvent{Actor: actorOf(sess, r), Action: "totp_enroll", OK: false,
					Remote: s.clientIP(r), Detail: "换绑未通过当前验证码/口令校验"})
				s.writeError(w, http.StatusForbidden, "reauth_required",
					"两步验证已启用，换绑需要再验证一次身份",
					"请带上当前生效的验证码（current_code）或登录口令（password）")
				return
			}
		}
		if !verifyTOTP(pending, code, time.Now()) {
			recordAuth(authEvent{Actor: actorOf(sess, r), Action: "totp_enroll", OK: false,
				Remote: s.clientIP(r), Detail: "验证码校验失败"})
			s.writeError(w, http.StatusUnprocessableEntity, "invalid_totp",
				"验证码不对：请确认认证器已加入该密钥、且手机时间与服务器一致",
				"密钥**仍未启用**；要换一把密钥请不带 code 重新调用")
			return
		}
		// 待确认 → 生效：这一步才允许改状态。
		s.totp.set(pending)
		s.totpPending.set("")
		s.totpOn.Store(true)
		recordAuth(authEvent{Actor: actorOf(sess, r), Action: "totp_enroll", OK: true,
			Remote: s.clientIP(r), Detail: "已校验并启用"})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"totp_enabled": true,
			"otpauth_url":  totpURI(issuer, account, pending),
			"warnings": []string{
				"已启用（本次运行）。要持久化请把密钥写入配置的 admin.totp_secret，并把 admin.totp_enabled 设为 true；否则重启后会回到未启用。",
			},
		})
		return
	}

	// ---- 不带验证码 = 生成（或重生）密钥，暂不激活 ----
	secret, err := generateTOTPSecret()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "generate_failed", "生成密钥失败", err.Error())
		return
	}
	// **只写待确认密钥，不动生效状态**：原先这里还写了 `s.totp.set(secret)` +
	// `s.totpOn.Store(false)`，等于用一次普通写请求把两步验证关掉。
	// 要真正解绑请走 `POST /totp/disable`（需账号口令）。
	s.totpPending.set(secret)
	recordAuth(authEvent{Actor: actorOf(sess, r), Action: "totp_enroll", OK: true,
		Remote: s.clientIP(r), Detail: "已生成密钥，待校验"})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"secret":      secret,
		"otpauth_url": totpURI(issuer, account, secret),
		// 如实回报：生成待确认密钥**不改变**当前启用状态
		// （已启用时这里仍然是 true —— 这正是修复的重点）。
		"totp_enabled": s.totpEnabled(),
		"pending":      true,
		// 前端目前只有"绑定/重绑"一个按钮、不会回传验证码，
		// 所以这里必须把"怎么真正启用"讲清楚，而不是让它看起来已经生效。
		"next_step": "把密钥填进认证器 App，然后带认证器当前验证码再调用一次本接口" +
			"（{\"code\": \"123456\"}）即可启用；或直接把密钥写进配置的 admin.totp_secret 并重启。",
		"warnings": []string{"密钥已生成但**尚未启用** —— 未校验过验证码就激活，填错一位就会把管理员锁在外面。"},
	})
}

// handleTOTPDisable 解绑 TOTP。
//
// 需要**账号口令**而不是会话：管理员最需要它的场合恰恰是"认证器丢了、进不去"，
// 那时候没有会话可用。它与登录共用同一套失败封禁，避免变成口令爆破入口。
func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	// 解绑是**改状态**的操作，跨站防护不能省。
	// 它不要求会话（"认证器丢了"也要能解绑），但那与"要不要防跨站"是两件事：
	// 只有账号口令 + 一个能跨站自动提交的表单，本来是可以被诱导触发的。
	if !s.requireSameSite(w, r) {
		return
	}
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
		return
	}
	ip := s.clientIP(r)
	wantUser := s.o.Config.Admin.Username
	if strings.TrimSpace(wantUser) == "" {
		wantUser = "admin"
	}
	if !subtleEqual(req.Username, wantUser) || !verifyPassword(s.login.get(), req.Password) {
		s.loginFails.Add(1)
		// 与登录共用同一套封禁（audit 01-F-02 的落地）：
		// 这里也是"猜口令"的入口，各算一套等于把可尝试次数翻倍。
		if banned, until := s.loginThrottle.fail(ip); banned {
			recordAuth(authEvent{Actor: req.Username, Action: "totp_disable", OK: false,
				Remote: ip, Detail: fmt.Sprintf("失败过多，封禁至 %s", until.Format(time.RFC3339))})
			w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
			s.writeError(w, http.StatusTooManyRequests, "locked_out", "尝试次数过多，已临时封禁", "")
			return
		}
		recordAuth(authEvent{Actor: req.Username, Action: "totp_disable", OK: false, Remote: ip})
		s.writeError(w, http.StatusUnauthorized, "invalid_credentials", "用户名或口令不对", "")
		return
	}
	s.loginThrottle.success(ip)
	s.totp.set("")
	s.totpOn.Store(false)
	recordAuth(authEvent{Actor: req.Username, Action: "totp_disable", OK: true, Remote: ip})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "totp_enabled": false,
		"warnings": []string{"已解绑（本次运行）。如果配置里还写着 admin.totp_enabled: true，请一并改掉，否则下次重启又会要求两步验证。"},
	})
}

// handleGatePathRotate 生成一个新的控制台挂载路径 token。
//
// **刻意不做"运行时热改"**：挂载路径在启动时就被烘进了三个地方 ——
// mux 的路由、静态资源的服务前缀、以及注入到 SPA 里的 <base href>。
// 运行时换路径意味着要在服务过程中搬走一个正在被浏览器使用的挂载点，
// 结果多半是"管理员自己把自己踢出控制台"。
// 所以这里只做**生成**（这本来是最容易写错的一步：随机性要够），
// 然后明确告诉运维改哪里、要重启。
func (s *Server) handleGatePathRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	if !s.o.Config.Admin.Gate.Enabled {
		s.writeError(w, http.StatusPreconditionFailed, "gate_disabled",
			"门槛未启用，没有挂载路径可轮换", "先启用 admin.gate 再轮换")
		return
	}
	token, err := generatePassword()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "generate_failed", "生成 token 失败", err.Error())
		return
	}
	// token 要放进 URL 路径，去掉可能引起歧义的字符（-/ _ 之外的分隔符）。
	token = sanitizePathToken(token)
	if len(token) < 24 {
		s.writeError(w, http.StatusInternalServerError, "generate_failed", "生成的 token 太短", "")
		return
	}
	sess, _ := s.currentSession(r)
	recordAuth(authEvent{Actor: actorOf(sess, r), Action: "gate_path_rotate", OK: true,
		Remote: s.clientIP(r), Detail: "已生成新 token（需改配置并重启）"})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"token":         token,
		"mount":         "/" + token + "/",
		"current_mount": s.mount,
		"next_step": "把 admin.gate.path_token 写成上面这个值，然后重启进程。" +
			"为什么不能热改：挂载路径在启动时已烘进 mux 路由、静态资源前缀与 SPA 的 <base href>，" +
			"运行中搬走挂载点会把正在使用它的浏览器踢出控制台。",
		"warnings": []string{
			"token 只显示这一次，请立刻保存。",
			"重启后旧的挂载路径会立刻失效；如果控制台挂在反向代理后面，记得同步改代理规则。",
		},
	})
}

// sanitizePathToken 把随机口令收敛成适合放进 URL 路径的 token。
func sanitizePathToken(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		}
	}
	if b.Len() > 40 {
		return b.String()[:40]
	}
	return b.String()
}

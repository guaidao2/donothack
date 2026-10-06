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
			_ = cw.Write([]string{
				e.Ts.Format(time.RFC3339), e.TxID, e.ClientIP, e.Method, e.Path,
				e.Verdict, strconv.Itoa(e.Score), e.RuleID, e.Category, e.Severity,
				e.Target, e.Detail, strconv.Itoa(e.Status),
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

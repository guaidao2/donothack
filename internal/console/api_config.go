package console

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"donothack/internal/notify"

	"gopkg.in/yaml.v3"

	"donothack/internal/config"
	"donothack/internal/control"
)

// 本文件实现"磁盘上的配置 vs 正在跑的配置"的差异与热重载。
//
// 为什么不做通用的 PUT /config：
// WAF 的配置项里**大部分改不了**（监听地址、上游、TLS、real_ip 都要重建组件），
// 一个"接受任意字段、悄悄忽略改不了的那些"的接口比没有更危险 ——
// 运维以为改生效了，实际重启后才是新的。所以这里：
//   - GET  /config/diff   告诉你哪些字段变了、哪些能热改、哪些要重启
//   - POST /config/reload 只应用**能热改**的那部分，其余如实报告"需要重启"
//   - PUT  /config        直接拒绝，并指路到对应的专用端点

// hotFieldPrefixes 是支持热改的配置路径前缀。
//
// 判定标准：改它不需要重建监听器/连接池/TLS 上下文，且数据面能原子换掉。
var hotFieldPrefixes = []string{
	"engine.mode",
	"engine.inbound_anomaly_threshold",
	"engine.ban_on_block",
	"engine.block_ban_duration",
	"engine.fail_mode",
	"ratelimit.",
	"block_page.",
	"rules.dir",
	"rules.files",
	"rules.self_test",
	"log.level",
	"log.access_mode",
	"log.access_sample_ratio",
}

// restartFieldPrefixes 是明确要重启的字段（给运维一句准话）。
var restartFieldPrefixes = []string{
	"listen.",
	"upstream.",
	"tls.",
	"real_ip.",
	"metrics.",
	"admin.addr",
	"admin.tls.",
	"admin.gate.",
	"profile",
}

type configDiffEntry struct {
	Path   string `json:"path"`
	Old    any    `json:"old"`
	New    any    `json:"new"`
	Hot    bool   `json:"hot"`
	Action string `json:"action"`
}

// handleConfigDiff 比较磁盘配置与运行中的配置。
func (s *Server) handleConfigDiff(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	path := s.o.Config.Path
	if strings.TrimSpace(path) == "" {
		s.writeError(w, http.StatusPreconditionFailed, "no_config_path",
			"不知道配置文件路径，无法比较", "请用 -c 指定配置文件启动")
		return
	}
	disk, err := config.Load(path)
	if err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "invalid_config",
			"磁盘上的配置无法加载（改坏了？）", err.Error())
		return
	}
	oldMap := configToMap(s.o.Config)
	newMap := configToMap(disk)

	var entries []configDiffEntry
	diffMaps("", oldMap, newMap, &entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	hot, restart := 0, 0
	for _, e := range entries {
		if e.Hot {
			hot++
		} else {
			restart++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config_path":   path,
		"changed":       len(entries),
		"hot":           hot,
		"needs_restart": restart,
		"diff":          entries,
		"note": "「能热改」的项可以用 POST /config/reload 立即生效；" +
			"其余项需要重启进程。凭据类字段已脱敏，不参与比较。",
	})
}

// handleConfigReload 把磁盘配置里"能热改"的部分应用进来。
func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	path := s.o.Config.Path
	if strings.TrimSpace(path) == "" {
		s.writeError(w, http.StatusPreconditionFailed, "no_config_path", "不知道配置文件路径", "")
		return
	}
	disk, err := config.Load(path)
	if err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "invalid_config",
			"磁盘上的配置无法加载，已保留当前运行配置", err.Error())
		return
	}

	var applied, needsRestart []string

	// 限速
	if !sameRateLimit(s.o.Config, disk) {
		st := control.RateLimitState{
			Enabled:      disk.RateLimit.Enabled,
			RPS:          float64(disk.RateLimit.DefaultRPS),
			Burst:        float64(disk.RateLimit.DefaultBurst),
			BanAfterHits: disk.RateLimit.BanAfterHits,
			BanWindow:    disk.RateLimit.BanWindow.D(),
			BanDuration:  disk.RateLimit.BanDuration.D(),
			Whitelist:    disk.RateLimit.Whitelist,
		}
		sess, _ := s.currentSession(r)
		if _, _, err := s.o.Control.Apply(control.SetRateLimit{
			Enabled: &st.Enabled, RPS: &st.RPS, Burst: &st.Burst,
			BanAfterHits: &st.BanAfterHits, BanWindow: &st.BanWindow,
			BanDuration: &st.BanDuration, Whitelist: st.Whitelist,
		}, actorOf(sess, r), s.clientIP(r)); err != nil {
			s.writeError(w, http.StatusUnprocessableEntity, "apply_failed",
				"限速配置应用失败，已回滚", err.Error())
			return
		}
		applied = append(applied, "ratelimit")
	}

	// 拦截页参数
	if !sameBlockPage(s.o.Config, disk) {
		sess, _ := s.currentSession(r)
		if _, _, err := s.o.Control.Apply(control.SetBlockPageOptions{
			Status:      disk.BlockPage.Status,
			Branding:    boolPtr(disk.BlockPage.BrandingOn()),
			ProductName: disk.BlockPage.ProductName,
			ProductURL:  disk.BlockPage.ProductURL,
			Contact:     disk.BlockPage.Contact,
			Title:       disk.BlockPage.Title,
		}, actorOf(sess, r), s.clientIP(r)); err != nil {
			s.writeError(w, http.StatusUnprocessableEntity, "apply_failed",
				"拦截页配置应用失败，已回滚", err.Error())
			return
		}
		applied = append(applied, "block_page")
	}

	// 规则目录/文件变了 → 重载
	if s.o.Config.Rules.Dir != disk.Rules.Dir || strings.Join(s.o.Config.Rules.Files, ",") != strings.Join(disk.Rules.Files, ",") {
		sess, _ := s.currentSession(r)
		if _, _, err := s.o.Control.Apply(control.ReloadRules{
			Dir: disk.Rules.Dir, Files: disk.Rules.Files,
		}, actorOf(sess, r), s.clientIP(r)); err != nil {
			s.writeError(w, http.StatusUnprocessableEntity, "reload_failed",
				"规则重载失败（自测不过会整批拒绝），已保留原规则集", err.Error())
			return
		}
		applied = append(applied, "rules")
	}

	// 其余差异如实报告"需要重启"
	oldMap := configToMap(s.o.Config)
	newMap := configToMap(disk)
	var entries []configDiffEntry
	diffMaps("", oldMap, newMap, &entries)
	for _, e := range entries {
		if !e.Hot {
			needsRestart = append(needsRestart, e.Path)
		}
	}
	sort.Strings(needsRestart)

	// 进程内的配置对象也换成新的：至少让 /config 的读接口反映磁盘内容。
	// 注意：**这不代表监听地址之类的已经变了** —— 那些必须重启。
	s.o.Config.Rules = disk.Rules

	sess, _ := s.currentSession(r)
	recordAuth(authEvent{Actor: actorOf(sess, r), Action: "config_reload", OK: true,
		Remote: s.clientIP(r), Detail: strings.Join(applied, ",")})

	warnings := []string{}
	if len(applied) == 0 {
		warnings = append(warnings, "没有检测到可热改的差异")
	} else {
		warnings = append(warnings, "已热改："+strings.Join(applied, "、"))
	}
	if len(needsRestart) > 0 {
		warnings = append(warnings, "以下字段**必须重启进程**才生效："+strings.Join(needsRestart, "、"))
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(), Warnings: warnings})
}

// handleConfigPut 明确拒绝通用配置写入，并指路到专用端点。
func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	s.writeError(w, http.StatusMethodNotAllowed, "use_specific_endpoint",
		"不支持整体写配置：大部分配置项改了必须重启，静默忽略会让人以为改生效了",
		"限速走 PUT /ratelimit；拦截页走 PUT /block-page；规则走 POST /rulesets/reload；"+
			"比对差异与热重载走 GET /config/diff 与 POST /config/reload")
}

// ---------------------------------------------------------------- 工具

func configToMap(c *config.Config) map[string]any {
	raw, err := yaml.Marshal(c)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return map[string]any{}
	}
	if m == nil {
		m = map[string]any{}
	}
	// 凭据类字段不参与比较（否则 diff 会把脱敏后的 "***" 当成真实变化）
	scrubSecrets(m)
	return m
}

func scrubSecrets(m map[string]any) {
	if admin, ok := m["admin"].(map[string]any); ok {
		delete(admin, "password_hash")
		delete(admin, "api_token")
		if gate, ok := admin["gate"].(map[string]any); ok {
			delete(gate, "password_hash")
			// path_token 是"额外遮挡"，值变了确实要重启，但它是凭据，不回显；
			// 这里用"是否设置"来代替比较。
			if v, exists := gate["path_token"]; exists {
				gate["path_token"] = v != "" && v != nil
			}
		}
	}
}

func diffMaps(prefix string, oldM, newM map[string]any, out *[]configDiffEntry) {
	keys := map[string]bool{}
	for k := range oldM {
		keys[k] = true
	}
	for k := range newM {
		keys[k] = true
	}
	for k := range keys {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		ov, nv := oldM[k], newM[k]
		om, oIsMap := ov.(map[string]any)
		nm, nIsMap := nv.(map[string]any)
		if oIsMap && nIsMap {
			diffMaps(path, om, nm, out)
			continue
		}
		if fmt.Sprint(ov) == fmt.Sprint(nv) {
			continue
		}
		hot := matchesPrefix(path, hotFieldPrefixes)
		action := "需要重启进程"
		if hot {
			action = "可热改（POST /config/reload）"
		} else if matchesPrefix(path, restartFieldPrefixes) {
			action = "需要重启进程"
		}
		*out = append(*out, configDiffEntry{
			Path: path, Old: ov, New: nv, Hot: hot, Action: action,
		})
	}
}

func matchesPrefix(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == strings.TrimSuffix(p, ".") || strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func sameRateLimit(a, b *config.Config) bool {
	return a.RateLimit.Enabled == b.RateLimit.Enabled &&
		a.RateLimit.DefaultRPS == b.RateLimit.DefaultRPS &&
		a.RateLimit.DefaultBurst == b.RateLimit.DefaultBurst &&
		a.RateLimit.BanAfterHits == b.RateLimit.BanAfterHits &&
		a.RateLimit.BanWindow == b.RateLimit.BanWindow &&
		a.RateLimit.BanDuration == b.RateLimit.BanDuration &&
		strings.Join(a.RateLimit.Whitelist, ",") == strings.Join(b.RateLimit.Whitelist, ",")
}

func sameBlockPage(a, b *config.Config) bool {
	return a.BlockPage.Status == b.BlockPage.Status &&
		a.BlockPage.BrandingOn() == b.BlockPage.BrandingOn() &&
		a.BlockPage.ProductName == b.BlockPage.ProductName &&
		a.BlockPage.ProductURL == b.BlockPage.ProductURL &&
		a.BlockPage.Contact == b.BlockPage.Contact &&
		a.BlockPage.Title == b.BlockPage.Title
}

func boolPtr(v bool) *bool { return &v }

// ---------------------------------------------------------------- 告警通道

// handleNotify 读取或更新告警通道配置。
//
// 与配置文件的取舍：`alert.webhook` 改在内存里立即生效；要持久化请改配置文件后
// 用 POST /config/reload。**不回显 webhook 里的凭据**（很多 IM 机器人 URL 里带 token）。
func (s *Server) handleNotify(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireRead(w, r) {
			return
		}
		out := map[string]any{
			"enabled":            s.o.Config.Alert.Enabled,
			"webhook":            redactWebhook(s.o.Config.Alert.Webhook),
			"webhook_configured": s.o.Config.Alert.Webhook != "",
		}
		if s.o.Notifier != nil {
			out["stats"] = s.o.Notifier.Stats()
		}
		writeJSON(w, http.StatusOK, out)

	case http.MethodPut:
		if !s.requireWrite(w, r) {
			return
		}
		var req struct {
			Enabled *bool   `json:"enabled"`
			Webhook *string `json:"webhook"`
		}
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
			return
		}
		var warnings []string
		if req.Enabled != nil {
			s.o.Config.Alert.Enabled = *req.Enabled
		}
		if req.Webhook != nil {
			wh := strings.TrimSpace(*req.Webhook)
			if wh != "" && !strings.HasPrefix(wh, "http://") && !strings.HasPrefix(wh, "https://") {
				s.writeError(w, http.StatusUnprocessableEntity, "invalid_webhook",
					"webhook 必须以 http:// 或 https:// 开头", "")
				return
			}
			s.o.Config.Alert.Webhook = wh
		}
		// 重新构造发送器（旧的需要停掉，避免 goroutine 泄漏）
		if s.o.Notifier != nil {
			s.o.Notifier.Close()
		}
		s.o.Notifier = notify.New(notify.Options{
			Enabled:  s.o.Config.Alert.Enabled,
			Webhook:  s.o.Config.Alert.Webhook,
			Instance: s.o.Config.Upstream.URL,
		})
		// 数据面也要换（否则拦截时的告警还打到旧地址）
		if s.o.ApplyNotifier != nil {
			s.o.ApplyNotifier(s.o.Notifier)
		}
		sess, _ := s.currentSession(r)
		recordAuth(authEvent{Actor: actorOf(sess, r), Action: "notify_set", OK: true, Remote: s.clientIP(r)})
		warnings = append(warnings, "已生效（本次运行）；要持久化请改配置文件里的 alert 段后执行 POST /config/reload")
		if s.o.Config.Alert.Enabled && s.o.Config.Alert.Webhook == "" {
			warnings = append(warnings, "已启用但没配 webhook，实际不会发送任何告警")
		}
		writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(), Warnings: warnings})

	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只支持 GET / PUT", "")
	}
}

// handleNotifyTest 往 webhook 发一条测试告警（同步，直接回结果）。
func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	if s.o.Notifier == nil || !s.o.Notifier.Enabled() {
		s.writeError(w, http.StatusPreconditionFailed, "notify_disabled",
			"告警未启用或未配置 webhook", "先 PUT /notify 配好再测")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	err := s.o.Notifier.Send(ctx, notify.Event{
		Kind:     "test",
		At:       time.Now(),
		Severity: "info",
		Detail:   "这是一条来自 donothack 控制台的测试告警",
		TxID:     "console-test",
		Verdict:  "test",
	})
	sess, _ := s.currentSession(r)
	if err != nil {
		recordAuth(authEvent{Actor: actorOf(sess, r), Action: "notify_test", OK: false,
			Remote: s.clientIP(r), Detail: err.Error()})
		s.writeError(w, http.StatusBadGateway, "webhook_failed", "测试告警发送失败", err.Error())
		return
	}
	recordAuth(authEvent{Actor: actorOf(sess, r), Action: "notify_test", OK: true, Remote: s.clientIP(r)})
	writeJSON(w, http.StatusOK, okResponse{OK: true, Warnings: []string{"测试告警已送达 webhook"}})
}

// redactWebhook 只回显 host 与 path 的前缀，不回显完整 URL。
//
// 很多 IM 机器人的 webhook URL 里直接带着 token，回显等于把它交给浏览器。
func redactWebhook(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "://"); i >= 0 {
		rest := u[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			host := rest[:j]
			path := rest[j:]
			if len(path) > 12 {
				path = path[:12] + "…"
			}
			return u[:i+3] + host + path
		}
	}
	return "（已配置）"
}

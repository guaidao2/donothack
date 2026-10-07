package console

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"donothack/internal/control"
	"donothack/internal/rules"
)

// 本文件是例外与 IP 名单的控制台端点。
//
// 这两块是**误报治理**的手段：
// 一条规则误伤业务时，运维不该只有"把规则关了"这一个选择 ——
// 那会连真正的攻击一起放过去。例外允许"只对这条路径/这个来源放宽"，
// 而且强制写清原因与过期时间。

// exceptionView 是例外的对外视图。
type exceptionView struct {
	ID              string   `json:"id"`
	Reason          string   `json:"reason"`
	Expires         string   `json:"expires"`
	ExpiresIn       string   `json:"expires_in"`
	Paths           []string `json:"paths,omitempty"`
	Methods         []string `json:"methods,omitempty"`
	SourceIPs       []string `json:"source_ips,omitempty"`
	DisableRules    []string `json:"disable_rules,omitempty"`
	DisableCategory []string `json:"disable_categories,omitempty"`
	SkipRateLimit   bool     `json:"skip_ratelimit,omitempty"`
	Mode            string   `json:"mode"`
	Source          string   `json:"source"`
	// Managed 表示这条例外由控制台维护（false = 来自规则文件，控制台只读）。
	Managed bool `json:"managed"`
	Expired bool `json:"expired"`
}

func viewOfException(ex *rules.Exception, managed bool) exceptionView {
	v := exceptionView{
		ID: ex.ID, Reason: ex.Reason,
		Expires:   ex.Expires.Format(time.RFC3339),
		ExpiresIn: time.Until(ex.Expires).Round(time.Hour).String(),
		Paths:     ex.Paths, Methods: ex.Methods, SourceIPs: ex.SourceIPs,
		DisableRules: ex.DisableRules, DisableCategory: ex.DisableCategory,
		SkipRateLimit: ex.SkipRateLimit, Mode: ex.Mode,
		Source: ex.Source.String(), Managed: managed,
		Expired: time.Now().After(ex.Expires),
	}
	if v.Mode == "" {
		v.Mode = "skip"
	}
	return v
}

// handleExceptions 处理 /exceptions 的读写。
func (s *Server) handleExceptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireRead(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"exceptions": s.allExceptions(),
			"note": "来自规则文件的例外在控制台里只读（要改请改 YAML）；" +
				"控制台新建的例外只作用于内存，重启会丢失。",
		})

	case http.MethodPost:
		if !s.requireWrite(w, r) {
			return
		}
		var req exceptionRequest
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
			return
		}
		ex, err := req.toException(s.nextExceptionID())
		if err != nil {
			s.writeError(w, http.StatusUnprocessableEntity, "invalid_exception", "例外不合法", err.Error())
			return
		}
		snap := s.o.Control.Snapshot()
		list := append(append([]*rules.Exception{}, snap.Exceptions...), ex)
		s.applyExceptions(w, r, list, "新建例外 "+ex.ID)
		return

	case http.MethodPatch:
		if !s.requireWrite(w, r) {
			return
		}
		id := exceptionIDFromPath(r.URL.Path, "", "/api/v1/exceptions")
		if id == "" {
			s.writeError(w, http.StatusBadRequest, "bad_request", "缺少例外 ID", "")
			return
		}
		var req exceptionRequest
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
			return
		}
		snap := s.o.Control.Snapshot()
		list := make([]*rules.Exception, 0, len(snap.Exceptions))
		found := false
		for _, ex := range snap.Exceptions {
			if ex.ID != id {
				list = append(list, ex)
				continue
			}
			nw, err := req.toException(id)
			if err != nil {
				s.writeError(w, http.StatusUnprocessableEntity, "invalid_exception", "例外不合法", err.Error())
				return
			}
			list = append(list, nw)
			found = true
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "not_found",
				"控制台里没有这条例外（它可能来自规则文件，那样只能改 YAML）", id)
			return
		}
		s.applyExceptions(w, r, list, "修改例外 "+id)
		return

	case http.MethodDelete:
		if !s.requireWrite(w, r) {
			return
		}
		id := exceptionIDFromPath(r.URL.Path, "", "/api/v1/exceptions")
		if id == "" {
			s.writeError(w, http.StatusBadRequest, "bad_request", "缺少例外 ID", "")
			return
		}
		snap := s.o.Control.Snapshot()
		list := make([]*rules.Exception, 0, len(snap.Exceptions))
		found := false
		for _, ex := range snap.Exceptions {
			if ex.ID == id {
				found = true
				continue
			}
			list = append(list, ex)
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "not_found",
				"控制台里没有这条例外（来自规则文件的例外不能在控制台删除）", id)
			return
		}
		s.applyExceptions(w, r, list, "删除例外 "+id)
		return

	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只支持 GET / POST / PATCH / DELETE", "")
	}
}

type exceptionRequest struct {
	ID              string   `json:"id"`
	Reason          string   `json:"reason"`
	Expires         string   `json:"expires"`
	Paths           []string `json:"paths"`
	Methods         []string `json:"methods"`
	SourceIPs       []string `json:"source_ips"`
	DisableRules    []string `json:"disable_rules"`
	DisableCategory []string `json:"disable_categories"`
	SkipRateLimit   bool     `json:"skip_ratelimit"`
	Mode            string   `json:"mode"`
	// ExpiresIn 是便利字段：写 "72h" 比写绝对时间更符合"临时放行"的直觉。
	ExpiresIn string `json:"expires_in"`
}

func (req exceptionRequest) toException(id string) (*rules.Exception, error) {
	if strings.TrimSpace(req.ID) != "" {
		id = strings.TrimSpace(req.ID)
	}
	expires := time.Time{}
	switch {
	case strings.TrimSpace(req.ExpiresIn) != "":
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			return nil, fmt.Errorf("expires_in 解析失败：%w", err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("expires_in 必须为正")
		}
		expires = time.Now().Add(d)
	case strings.TrimSpace(req.Expires) != "":
		t, err := time.Parse(time.RFC3339, req.Expires)
		if err != nil {
			if t2, err2 := time.Parse("2006-01-02", req.Expires); err2 == nil {
				t = t2
			} else {
				return nil, fmt.Errorf("expires 解析失败（用 RFC3339 或 2006-01-02）：%w", err)
			}
		}
		expires = t
	default:
		return nil, fmt.Errorf("必须给 expires 或 expires_in —— 例外没有到期时间就会变成永久后门")
	}
	return rules.NewException(id, req.Reason, expires, req.Paths, req.Methods, req.SourceIPs,
		req.DisableRules, req.DisableCategory, req.SkipRateLimit, req.Mode)
}

func (s *Server) applyExceptions(w http.ResponseWriter, r *http.Request, list []*rules.Exception, action string) {
	sess, _ := s.currentSession(r)
	_, warnings, err := s.o.Control.Apply(control.SetExceptions{List: list}, actorOf(sess, r), s.clientIP(r))
	if err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "exception_failed", action+" 失败，已回滚", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(), Warnings: warnings})
}

// allExceptions 合并"规则文件里的例外"与"控制台维护的例外"。
func (s *Server) allExceptions() []exceptionView {
	out := []exceptionView{}
	snap := s.o.Control.Snapshot()
	if snap == nil {
		return out
	}
	if snap.RuleSet != nil {
		for _, ex := range snap.RuleSet.Exceptions() {
			out = append(out, viewOfException(ex, false))
		}
	}
	for _, ex := range snap.Exceptions {
		out = append(out, viewOfException(ex, true))
	}
	return out
}

func (s *Server) nextExceptionID() string {
	snap := s.o.Control.Snapshot()
	max := 0
	if snap != nil {
		for _, ex := range snap.Exceptions {
			var n int
			if _, err := fmt.Sscanf(ex.ID, "EXC-C-%d", &n); err == nil && n > max {
				max = n
			}
		}
	}
	return fmt.Sprintf("EXC-C-%04d", max+1)
}

// exceptionIDFromPath 从路径里取出 ID（ID 里不会有斜杠，直接切即可）。
func exceptionIDFromPath(path, mount, prefix string) string {
	p := strings.TrimPrefix(path, mount+prefix)
	return strings.Trim(p, "/")
}

// ---------------------------------------------------------------- IP 名单

func (s *Server) handleIPLists(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireRead(w, r) {
			return
		}
		snap := s.o.Control.Snapshot()
		if snap == nil {
			writeJSON(w, http.StatusOK, map[string]any{"allow": []any{}, "deny": []any{}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"allow":       snap.IPLists.Allow,
			"deny":        snap.IPLists.Deny,
			"deny_status": snap.IPLists.DenyStatus,
			"semantics": "拒绝名单命中即拦；允许名单命中则跳过检测与限速。" +
				"允许名单不是「只允许这些 IP」—— 配错会把全站挡在外面。",
		})

	case http.MethodPost:
		if !s.requireWrite(w, r) {
			return
		}
		var req struct {
			Kind  string `json:"kind"` // allow | deny
			Value string `json:"value"`
		}
		if err := decodeJSON(r, &req); err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
			return
		}
		kind := strings.ToLower(strings.TrimSpace(req.Kind))
		if kind != "allow" && kind != "deny" {
			s.writeError(w, http.StatusBadRequest, "bad_request", "kind 必须是 allow 或 deny", "")
			return
		}
		if strings.TrimSpace(req.Value) == "" {
			s.writeError(w, http.StatusBadRequest, "bad_request", "value 不能为空", "")
			return
		}
		snap := s.o.Control.Snapshot()
		next := control.IPListState{
			Allow:      append([]string{}, snap.IPLists.Allow...),
			Deny:       append([]string{}, snap.IPLists.Deny...),
			DenyStatus: snap.IPLists.DenyStatus,
		}
		if kind == "allow" {
			next.Allow = append(next.Allow, strings.TrimSpace(req.Value))
		} else {
			next.Deny = append(next.Deny, strings.TrimSpace(req.Value))
		}
		s.applyIPLists(w, r, next, "新增 IP "+kind+" 条目")
		return

	case http.MethodDelete:
		if !s.requireWrite(w, r) {
			return
		}
		// 走 EscapedPath：CIDR 里的 "/" 会被 URL 编码成 %2F，
		// 而 r.URL.Path 已经把它解码回 "/" 了，直接用会切错。
		raw := strings.TrimPrefix(r.URL.EscapedPath(), "/api/v1/ip-lists/")
		value, err := url.PathUnescape(raw)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "bad_request", "路径里的条目无法解码", err.Error())
			return
		}
		value = strings.TrimSpace(value)
		if value == "" {
			s.writeError(w, http.StatusBadRequest, "bad_request", "缺少要删除的条目", "")
			return
		}
		snap := s.o.Control.Snapshot()
		next := control.IPListState{DenyStatus: snap.IPLists.DenyStatus}
		removed := false
		for _, v := range snap.IPLists.Allow {
			if strings.TrimSpace(v) == value {
				removed = true
				continue
			}
			next.Allow = append(next.Allow, v)
		}
		for _, v := range snap.IPLists.Deny {
			if strings.TrimSpace(v) == value {
				removed = true
				continue
			}
			next.Deny = append(next.Deny, v)
		}
		if !removed {
			s.writeError(w, http.StatusNotFound, "not_found", "名单里没有这个条目", value)
			return
		}
		s.applyIPLists(w, r, next, "删除 IP 条目 "+value)
		return

	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只支持 GET / POST / DELETE", "")
	}
}

func (s *Server) applyIPLists(w http.ResponseWriter, r *http.Request, st control.IPListState, action string) {
	sess, _ := s.currentSession(r)
	_, warnings, err := s.o.Control.Apply(control.SetIPLists{
		Allow: st.Allow, Deny: st.Deny, DenyStatus: st.DenyStatus,
	}, actorOf(sess, r), s.clientIP(r))
	if err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "iplist_failed", action+" 失败，已回滚", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(), Warnings: warnings})
}

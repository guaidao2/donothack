package console

import (
	"context"
	"net/http"
	"strings"
	"time"

	"donothack/internal/control"
	"donothack/internal/rules"
	"donothack/internal/rulessync"
)

// rulesSyncReport 与最近一次结果的状态都放在 rulessync 包里 ——
// 控制台与 /readyz 读同一份事实，避免"控制台说换了、readyz 说没换"。
type rulesSyncReport = rulessync.LastResult

func setRulesSyncReport(r rulesSyncReport) { rulessync.SetLast(r) }

func lastRulesSyncReport() *rulesSyncReport { return rulessync.Last() }

// handleRulesSync 是"手动同步规则集"的入口：GET 看状态，POST 执行一次。
//
// 只做手动触发（不提供定时拉取）：换规则等于换检测策略，让每次变更都有人按下去、
// 留下一条审计，比"半夜自己换了一套规则"要好查得多。
//
// 顺序上刻意保持"先校验再替换"：rulessync.Apply 会在临时目录里用正式加载器
// 完整校验（含每条规则的正负样本自测），通过才替换本机规则目录；失败保持原状。
// 替换成功后再走既有的 control.Apply(ReloadRules) 热重载 —— 校验不过会整批拒绝并
// 保留正在生效的规则集。
func (s *Server) handleRulesSync(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.requireRead(w, r) {
			return
		}
		s.writeRulesSyncStatus(w)
	case http.MethodPost:
		if !s.requireWrite(w, r) {
			return
		}
		s.runRulesSync(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只支持 GET 与 POST", "")
	}
}

// writeRulesSyncStatus 报告当前规则集指纹、同步源与上次结果。
func (s *Server) writeRulesSyncStatus(w http.ResponseWriter) {
	if s.o.Control == nil || s.o.Control.Snapshot() == nil {
		s.writeError(w, http.StatusServiceUnavailable, "no_snapshot", "控制面尚未初始化", "")
		return
	}
	snap := s.o.Control.Snapshot()
	cfg := s.o.Config.Rules
	last := lastRulesSyncReport()
	version := ""
	if rs, err := rules.LoadDir(rules.DefaultOptions(), cfg.Dir, []string{"*.yaml", "*.yml"}); err == nil {
		version = rs.Version
	}
	out := map[string]any{
		"ok":            true,
		"dir":           cfg.Dir,
		"source":        cfg.SyncSource,
		"ref":           cfg.SyncRef,
		"rules_version": version,
		"snapshot":      snap.Version,
	}
	if last != nil {
		out["last"] = last
	}
	writeJSON(w, http.StatusOK, out)
}

// runRulesSync 执行一次同步。
func (s *Server) runRulesSync(w http.ResponseWriter, r *http.Request) {
	if s.o.Control == nil || s.o.Control.Snapshot() == nil {
		s.writeError(w, http.StatusServiceUnavailable, "no_snapshot", "控制面尚未初始化", "")
		return
	}
	cfg := s.o.Config.Rules
	sess, _ := s.currentSession(r)
	actor := actorOf(sess, r)

	report := rulesSyncReport{
		At:     time.Now(),
		Source: strings.TrimSpace(cfg.SyncSource),
		Ref:    strings.TrimSpace(cfg.SyncRef),
	}
	fail := func(status int, code, msg string, detail string) {
		report.OK = false
		report.Error = msg
		if detail != "" {
			report.Error = msg + "：" + detail
		}
		setRulesSyncReport(report)
		s.writeError(w, status, code, msg, detail)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	src := rulessync.Source{BaseURL: report.Source, Ref: report.Ref}
	hc := &http.Client{Timeout: 60 * time.Second}
	// Ref 留空时直接跟默认分支 —— 要的就是"最新规则"。
	// 应急场景里规则是修完就推的，等打 tag/发 Release 会白白拖一段时间，
	// 而这段时间里绕过一直可用。
	files, listURL, err := rulessync.Fetch(ctx, src, hc)
	if err != nil {
		fail(http.StatusBadGateway, "fetch_failed", "取规则集失败，本机规则未改动", err.Error())
		return
	}
	report.Source = listURL

	res, err := rulessync.Apply(cfg.Dir, files)
	if err != nil {
		fail(http.StatusUnprocessableEntity, "sync_rejected", "规则集未通过校验，已保持原状", err.Error())
		return
	}
	report.FromVersion, report.ToVersion, report.Files, report.Skipped = res.FromVersion, res.ToVersion, res.Files, res.Skipped

	if res.Skipped {
		report.OK = true
		setRulesSyncReport(report)
		writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(),
			Warnings: []string{"已是最新规则集（" + res.FromVersion + "），未做替换"}})
		return
	}

	// 落盘成功 → 热重载。校验不过会整批拒绝，正在生效的规则集不受影响。
	mut := control.ReloadRules{Dir: cfg.Dir, Files: cfg.Files}
	if _, _, err := s.o.Control.Apply(mut, actor, s.clientIP(r)); err != nil {
		fail(http.StatusUnprocessableEntity, "reload_failed",
			"规则已下载并通过自测，但热重载未生效（仍在使用原规则集；重启后会自动加载新的）", err.Error())
		return
	}
	report.OK = true
	setRulesSyncReport(report)
	writeJSON(w, http.StatusOK, okResponse{OK: true, SnapshotVersion: s.snapshotVersion(),
		Warnings: []string{"规则集已更新：" + res.FromVersion + " → " + res.ToVersion}})
}

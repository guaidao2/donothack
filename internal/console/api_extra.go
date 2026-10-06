package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"donothack/internal/blockpage"
	"donothack/internal/control"
	"donothack/internal/rules"
)

// 本文件是 P4 的补充端点：规则预览、事件实时流、备份与恢复。
//
// 共同纪律：**能预览的都必须能预览**。WAF 的配置改动一句话就能把线上打挂，
// 所以每个写操作都要有一个"先看看会怎样"的入口。

// ---------------------------------------------------------------- 规则预览

// handleRulesPreview 干跑一次规则变更，返回差异与统计，**不产生任何状态变更**。
//
// 三种用法：
//
//	{"yaml": "..."}     校验一段新规则并给出与当前规则集的差异
//	{"reload": true}    预演"从磁盘重载会变成什么样"
//	{}                  只回当前规则集统计
func (s *Server) handleRulesPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	var req struct {
		YAML   string `json:"yaml"`
		Name   string `json:"name"`
		Reload bool   `json:"reload"`
		// Disable 是"预演时也把这些规则停用"，用于"停用后还剩多少条"
		Disable []string `json:"disable"`
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
	before := snap.RuleSet

	var mut control.Mutation
	switch {
	case strings.TrimSpace(req.YAML) != "":
		name := req.Name
		if strings.TrimSpace(name) == "" {
			name = "preview.yaml"
		}
		mut = control.SetRulesFromSource{SourceName: name, YAML: req.YAML, Disable: req.Disable}
	case req.Reload:
		mut = control.ReloadRules{Dir: s.o.Config.Rules.Dir, Files: s.o.Config.Rules.Files,
			Disable: req.Disable}
	default:
		st := snap.RuleSet.Stats()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "changed": false, "stats": st})
		return
	}

	next, warnings, err := s.o.Control.Preview(mut)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": map[string]any{
				"code": "preview_failed", "message": "预演失败（这份规则不会被应用）", "detail": err.Error(),
			},
		})
		return
	}

	var after *rules.RuleSet
	if next != nil {
		after = next.RuleSet
	}
	diff := diffRulesets(before, after)
	st := rules.Stats{ByCategory: map[string]int{}, ByPhase: map[int]int{}}
	if after != nil {
		st = after.Stats()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"changed":  true,
		"diff":     diff,
		"warnings": warnings,
		"stats": map[string]any{
			"rules": st.Rules, "enabled": st.Enabled, "disabled": st.Disabled,
			"chains": st.Chains, "literal_rules": st.LiteralRules,
			"no_literal_rules": st.NoLiteralRules, "prefilter_nodes": st.PrefilterNodes,
			"by_category": st.ByCategory, "warnings": st.Warnings,
		},
	})
}

// RuleDiff 是两份规则集的差异。
//
// 只报 ID 与关键属性，不报正则与样本 —— 控制台读接口不该成为规则情报的出口。
type RuleDiff struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Modified []string `json:"modified"`
	Total    int      `json:"total_before"`
	TotalNew int      `json:"total_after"`
}

func diffRulesets(before, after *rules.RuleSet) RuleDiff {
	d := RuleDiff{}
	if before == nil && after == nil {
		return d
	}
	if before != nil {
		d.Total = len(before.Rules())
	}
	if after != nil {
		d.TotalNew = len(after.Rules())
	}
	index := func(rs *rules.RuleSet) map[string]*rules.CompiledRule {
		m := map[string]*rules.CompiledRule{}
		if rs == nil {
			return m
		}
		for _, r := range rs.Rules() {
			m[r.ID] = r
		}
		return m
	}
	oldM, newM := index(before), index(after)
	for id, nr := range newM {
		or, ok := oldM[id]
		if !ok {
			d.Added = append(d.Added, id)
			continue
		}
		// 关键属性变了才算"修改"（严重度、分数、类目、启停、动作）
		if or.Severity != nr.Severity || or.Score != nr.Score || or.Category != nr.Category ||
			or.Enabled != nr.Enabled || or.Action.Type != nr.Action.Type ||
			or.OperatorName != nr.OperatorName || strings.Join(or.TransformNames, ",") != strings.Join(nr.TransformNames, ",") {
			d.Modified = append(d.Modified, id)
		}
	}
	for id := range oldM {
		if _, ok := newM[id]; !ok {
			d.Removed = append(d.Removed, id)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Modified)
	return d
}

// ---------------------------------------------------------------- 事件实时流（SSE）

// handleEventsStream 推送新事件。
//
// 三条纪律：
//  1. **订阅数有界**（eventstore 里限制 8 个），订阅者跟不上就丢事件 —— 绝不阻塞数据面。
//  2. **连接有寿命**：最长 30 分钟就主动断开，避免代理/浏览器留下僵尸连接。
//  3. 定期发心跳注释行，防止中间设备把空闲连接掐掉。
func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	if s.o.Events == nil {
		s.writeError(w, http.StatusServiceUnavailable, "events_disabled",
			"事件存储未启用（需要 admin.enabled）", "")
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		s.writeError(w, http.StatusHTTPVersionNotSupported, "no_streaming",
			"当前连接不支持流式响应", "")
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	// 反向代理下要显式禁止缓冲，否则事件会被攒着不发
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fl.Flush()

	ch, cancel := s.o.Events.Subscribe()
	defer cancel()

	// 先告诉客户端当前订阅数（便于发现泄漏）
	_, _ = fmt.Fprintf(w, "event: hello\ndata: {\"subscribers\":%d,\"retained\":%d}\n\n",
		s.o.Events.Subscribers(), s.o.Events.Len())
	fl.Flush()

	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	deadline := time.NewTimer(30 * time.Minute)
	defer deadline.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			_, _ = fmt.Fprint(w, "event: bye\ndata: {\"reason\":\"stream lifetime reached\"}\n\n")
			fl.Flush()
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprintf(w, "event: event\ndata: %s\n\n", eventJSON(e)); err != nil {
				return
			}
			fl.Flush()
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

func eventJSON(e any) string {
	b, err := json.Marshal(e)
	if err != nil {
		return "{}"
	}
	// SSE 的 data 不能含裸换行；json.Marshal 已经把换行转义成 \n 了，
	// 但保险起见再挡一层。
	return strings.ReplaceAll(string(b), "\n", " ")
}

// ---------------------------------------------------------------- 备份与恢复

// BackupBundle 是备份包。
//
// **刻意不含任何凭据**：password_hash、api_token、门槛凭据一律不导出。
// 备份文件经常被随手放在运维机器上、丢进网盘，凭据进去就等于泄露。
type BackupBundle struct {
	Version    string    `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	Note       string    `json:"note"`

	Rules     []BackupFile `json:"rules"`
	BlockPage struct {
		HTML        string `json:"html"`
		Status      int    `json:"status"`
		Branding    bool   `json:"branding"`
		ProductName string `json:"product_name"`
		ProductURL  string `json:"product_url"`
		Contact     string `json:"contact"`
		Title       string `json:"title"`
	} `json:"block_page"`
	RateLimit struct {
		Enabled      bool     `json:"enabled"`
		RPS          float64  `json:"rps"`
		Burst        float64  `json:"burst"`
		BanAfterHits int      `json:"ban_after_hits"`
		BanWindow    string   `json:"ban_window"`
		BanDuration  string   `json:"ban_duration"`
		Whitelist    []string `json:"whitelist"`
	} `json:"ratelimit"`

	Snapshot string `json:"snapshot"`
}

// BackupFile 是备份里的一个规则文件。
type BackupFile struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

// handleBackup 导出配置备份（GET 可直接下载）。
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if !s.requireRead(w, r) {
		return
	}
	snap := s.o.Control.Snapshot()
	if snap == nil {
		s.writeError(w, http.StatusServiceUnavailable, "no_snapshot", "控制面尚未初始化", "")
		return
	}
	b := BackupBundle{
		Version:    s.o.Version,
		ExportedAt: time.Now(),
		Note: "此备份不含任何凭据（password_hash / api_token / 门槛凭据一律不导出）。" +
			"恢复只作用于内存；要持久化请把 rules 里的文件写回规则目录后调用 /rulesets/reload。",
		Snapshot: snap.Version,
	}
	for _, bf := range s.readRuleFiles() {
		b.Rules = append(b.Rules, bf)
	}
	b.BlockPage.HTML = snap.BlockPage.CustomHTML
	b.BlockPage.Status = snap.BlockPage.Options.Status
	b.BlockPage.Branding = snap.BlockPage.Options.Branding
	b.BlockPage.ProductName = snap.BlockPage.Options.ProductName
	b.BlockPage.ProductURL = snap.BlockPage.Options.ProductURL
	b.BlockPage.Contact = snap.BlockPage.Options.Contact
	b.BlockPage.Title = snap.BlockPage.Options.Title

	rl := snap.RateLimit
	b.RateLimit.Enabled = rl.Enabled
	b.RateLimit.RPS = rl.RPS
	b.RateLimit.Burst = rl.Burst
	b.RateLimit.BanAfterHits = rl.BanAfterHits
	b.RateLimit.BanWindow = rl.BanWindow.String()
	b.RateLimit.BanDuration = rl.BanDuration.String()
	b.RateLimit.Whitelist = rl.Whitelist

	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="donothack-backup-%s.json"`, time.Now().Format("20060102-150405")))
	writeJSON(w, http.StatusOK, b)
}

// readRuleFiles 读取规则目录下的文件内容（供备份）。
func (s *Server) readRuleFiles() []BackupFile {
	dir := s.o.Config.Rules.Dir
	pats := s.o.Config.Rules.Files
	if len(pats) == 0 {
		pats = []string{"*.yaml", "*.yml"}
	}
	seen := map[string]bool{}
	var out []BackupFile
	for _, pat := range pats {
		matches, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			continue
		}
		sort.Strings(matches)
		for _, f := range matches {
			if seen[f] {
				continue
			}
			seen[f] = true
			raw, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			out = append(out, BackupFile{Name: filepath.Base(f), Content: string(raw)})
		}
	}
	return out
}

// handleRestore 从备份恢复。
//
// 语义（**刻意保守**）：
//   - `?preview=1` 或 `{"preview":true}`：只校验并回报告诉你会变什么，不应用。
//   - 正式恢复：**只作用于内存**，不写回规则目录。
//     理由：恢复是容易点错的操作，出错代价应当是"重启后回到磁盘状态"，
//     而不是"磁盘上的规则文件被覆盖了"。
func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	var req struct {
		Bundle  BackupBundle `json:"bundle"`
		Preview bool         `json:"preview"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "备份包不是合法 JSON", err.Error())
		return
	}
	preview := req.Preview || r.URL.Query().Get("preview") == "1"

	// 备份里的规则是按文件存的，而 loader 一份文档只认一个 meta/version，
	// 所以合并成一份源（见 mergeRuleFiles）。合并前逐份校验，避免把坏文件混进来。
	var names []string
	for _, bf := range req.Bundle.Rules {
		if strings.TrimSpace(bf.Content) == "" {
			continue
		}
		names = append(names, bf.Name)
	}

	snap := s.o.Control.Snapshot()
	if snap == nil {
		s.writeError(w, http.StatusServiceUnavailable, "no_snapshot", "控制面尚未初始化", "")
		return
	}

	type step struct {
		Name string
		Mut  control.Mutation
		Skip bool
	}
	var steps []step
	if len(names) > 0 {
		// 把多份文件合成一份源：loader 的 version/meta 只认第一份，
		// 所以这里把后续文件的 rules 段落合并进第一份。
		merged, err := mergeRuleFiles(req.Bundle.Rules)
		if err != nil {
			s.writeError(w, http.StatusUnprocessableEntity, "invalid_backup",
				"备份里的规则文件无法合并", err.Error())
			return
		}
		steps = append(steps, step{Name: "rules", Mut: control.SetRulesFromSource{
			SourceName: "restore.yaml", YAML: merged,
		}})
	}
	if req.Bundle.BlockPage.HTML != "" || req.Bundle.BlockPage.Status != 0 {
		steps = append(steps, step{Name: "block_page", Mut: control.RestoreBlockPage{
			HTML: req.Bundle.BlockPage.HTML,
			File: s.blockPageFilePath(),
			Options: blockpage.Options{
				Status:      req.Bundle.BlockPage.Status,
				Branding:    req.Bundle.BlockPage.Branding,
				ProductName: req.Bundle.BlockPage.ProductName,
				ProductURL:  req.Bundle.BlockPage.ProductURL,
				Contact:     req.Bundle.BlockPage.Contact,
				Title:       req.Bundle.BlockPage.Title,
				Version:     s.o.Version,
			},
		}})
	}
	if len(steps) == 0 {
		s.writeError(w, http.StatusBadRequest, "empty_backup", "备份包里没有任何可恢复的内容", "")
		return
	}

	actor := "unknown"
	if sess, ok := s.currentSession(r); ok {
		actor = sess.User
	}

	// 预演：逐步干跑，只回报告
	if preview {
		cur := snap
		report := make([]map[string]any, 0, len(steps))
		for _, st := range steps {
			next, warnings, err := st.Mut.Apply(cur)
			entry := map[string]any{"step": st.Name, "ok": err == nil}
			if err != nil {
				entry["error"] = err.Error()
			} else {
				entry["warnings"] = warnings
				if next != nil {
					cur = next
					if next.RuleSet != nil {
						entry["rules"] = next.RuleSet.Stats().Rules
					}
				}
			}
			report = append(report, entry)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "preview": true, "steps": report,
			"note": "预演不产生任何状态变更",
		})
		return
	}

	// 正式恢复：逐步应用。**任一步失败即停止**，已应用的部分保留
	// （控制面的 Apply 本身是原子的；跨步之间无法回滚，所以顺序上先做校验最严的规则）。
	applied := make([]string, 0, len(steps))
	for _, st := range steps {
		_, warnings, err := s.o.Control.Apply(st.Mut, actor, s.clientIP(r))
		if err != nil {
			s.writeError(w, http.StatusUnprocessableEntity, "restore_failed",
				"恢复失败于步骤 "+st.Name+"（已应用的步骤保留，请检查后重试）",
				err.Error()+"；已应用："+strings.Join(applied, ", "))
			return
		}
		applied = append(applied, st.Name+"("+strings.Join(warnings, "；")+")")
	}
	writeJSON(w, http.StatusOK, okResponse{
		OK: true, SnapshotVersion: s.snapshotVersion(),
		Warnings: append([]string{
			"恢复只作用于内存，**没有写回磁盘**；要持久化请把备份里的规则文件写回规则目录并调用 /rulesets/reload",
		}, applied...),
	})
}

// mergeRuleFiles 把多个规则文件合并成一份 YAML。
//
// loader 只认一份文档的 meta/version，而备份是按文件存的，
// 所以这里把后续文件的 `rules:` 与 `exceptions:` 段落追加到第一份后面。
// 合并前逐份校验，避免把坏文件混进来。
func mergeRuleFiles(files []BackupFile) (string, error) {
	var head string
	var rulesBlocks []string
	var excBlocks []string
	for _, f := range files {
		content := strings.TrimRight(f.Content, "\n")
		if strings.TrimSpace(content) == "" {
			continue
		}
		// 先单独校验这一份（确保拼出来的东西是合法的）
		opts := rules.DefaultOptions()
		opts.SelfTest = false // 逐份校验时不跑自测（合并后再跑）
		if _, err := rules.LoadSource(opts, f.Name, []byte(content)); err != nil {
			return "", fmt.Errorf("%s：%w", f.Name, err)
		}
		if head == "" {
			head = content
			continue
		}
		rb, eb := extractSections(content)
		if rb != "" {
			rulesBlocks = append(rulesBlocks, rb)
		}
		if eb != "" {
			excBlocks = append(excBlocks, eb)
		}
	}
	if head == "" {
		return "", fmt.Errorf("没有有效的规则文件")
	}
	out := head
	for _, rb := range rulesBlocks {
		out += "\n" + rb
	}
	for _, eb := range excBlocks {
		out += "\n" + eb
	}
	return out, nil
}

// extractSections 从一份规则文件里抽出 rules 与 exceptions 段落的条目。
//
// 只做"按缩进切段"，不引 YAML 库 —— 这些内容马上还要交给严格 loader 校验，
// 这里做重活没有意义。
func extractSections(content string) (rulesBlock, excBlock string) {
	lines := strings.Split(content, "\n")
	var cur string
	var buf []string
	flush := func() {
		if len(buf) == 0 {
			return
		}
		body := strings.Join(buf, "\n")
		switch cur {
		case "rules":
			rulesBlock += body + "\n"
		case "exceptions":
			excBlock += body + "\n"
		}
		buf = nil
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "rules:") || strings.HasPrefix(line, "exceptions:") {
			flush()
			cur = strings.TrimSuffix(strings.TrimSpace(line), ":")
			buf = append(buf, line)
			continue
		}
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && !strings.HasPrefix(line, "#") {
			// 顶层键（version/meta 等）：结束当前段
			flush()
			cur = ""
			continue
		}
		if cur != "" {
			buf = append(buf, line)
		}
	}
	flush()
	return rulesBlock, excBlock
}

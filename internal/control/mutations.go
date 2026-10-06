package control

import (
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"donothack/internal/blockpage"
	"donothack/internal/rules"
)

// 本文件是控制面支持的具体变更。
//
// 每个变更都遵守同一条纪律：**在 Apply 里做完全部校验**（模板能不能编译、
// 规则能不能通过自测），不能等换上去之后才发现问题。
// 校验失败 → 返回 error → 控制面保持旧状态 → 数据面完全不受影响。

// ---------------------------------------------------------------- 引擎热参数

// SetEngine 改引擎的可热改参数（模式、阈值、命中即封禁）。
//
// 用途最要紧的是**应急切模式**：运维发现攻击已经在打，要把 detect 改成 block。
// 这条路以前是假的 —— `/config/reload` 返回"已热改"，而 WAF 还在 detect 放行
// 。
//
// 指针字段表示"这次要改它"，nil 表示保持不动（与其它变更一致的写法）。
type SetEngine struct {
	Mode               *string
	InboundThreshold   *int
	CategoryThresholds map[string]int
	BanOnBlock         *bool
	BlockBanDuration   *time.Duration
}

func (m SetEngine) Name() string { return "engine.set" }

func (m SetEngine) Apply(cur *State) (*State, []string, error) {
	next := *cur
	st := next.Engine
	var warnings []string

	if m.Mode != nil {
		mode := strings.TrimSpace(strings.ToLower(*m.Mode))
		switch mode {
		case "detect", "block", "mixed":
			st.Mode = mode
		default:
			return nil, nil, fmt.Errorf("engine.mode 只支持 detect / block / mixed，实际 %q", *m.Mode)
		}
	}
	if m.InboundThreshold != nil {
		if *m.InboundThreshold < 1 {
			return nil, nil, fmt.Errorf("engine.inbound_anomaly_threshold 至少为 1（实际 %d）", *m.InboundThreshold)
		}
		st.InboundThreshold = *m.InboundThreshold
	}
	if m.CategoryThresholds != nil {
		for cat, th := range m.CategoryThresholds {
			if th < 1 {
				return nil, nil, fmt.Errorf("类目 %s 的阈值至少为 1（实际 %d）", cat, th)
			}
		}
		st.CategoryThresholds = m.CategoryThresholds
	}
	if m.BanOnBlock != nil {
		st.BanOnBlock = *m.BanOnBlock
	}
	if m.BlockBanDuration != nil {
		if *m.BlockBanDuration < 0 {
			return nil, nil, fmt.Errorf("engine.block_ban_duration 不能为负")
		}
		st.BlockBanDuration = *m.BlockBanDuration
	}

	// 切到会拦截的模式时给一句警告：这是"立刻会开始 403"的语义变化，
	// 不该让人只从返回体里一个字段去推断。
	if m.Mode != nil && st.Mode != "detect" {
		warnings = append(warnings, fmt.Sprintf(
			"引擎模式已切到 %s：命中阈值的请求会**立刻开始被拦截**（原先是只记录）", st.Mode))
	}
	next.Engine = st
	return &next, warnings, nil
}

// ---------------------------------------------------------------- 拦截页

// SetBlockPageHTML 替换拦截页的自定义模板。
//
// 这是控制台里"改拦截页内容"的入口。空字符串表示恢复内置模板。
type SetBlockPageHTML struct {
	HTML string
	// File 非空时把模板落盘到这个路径（相对配置文件目录）；
	// 落盘失败**不影响本次变更**（内存里已经生效），但会作为警告返回。
	File string
	// WriteFile 是否真的写盘。
	WriteFile bool
}

func (m SetBlockPageHTML) Name() string { return "block_page.set_html" }

func (m SetBlockPageHTML) Apply(cur *State) (*State, []string, error) {
	html := m.HTML
	if strings.TrimSpace(html) == "" {
		html = "" // 空 → 内置模板
	}

	opts := cur.BlockPage.Options
	opts.CustomHTML = html
	r := blockpage.New(opts)
	if r.CustomError() != "" {
		// **编译失败就整次拒绝**：不能让一个语法错的模板换上去，
		// 那会让所有被拦请求都看到半成品页面。
		return nil, nil, fmt.Errorf("模板编译失败：%s", r.CustomError())
	}

	next := *cur
	next.BlockPage = BlockPageState{
		Options:    opts,
		CustomHTML: html,
		File:       cur.BlockPage.File,
		Renderer:   r,
	}
	next.Reason = "控制台修改拦截页"

	var warnings []string
	if m.WriteFile && m.File != "" {
		if err := writeTemplateFile(m.File, html); err != nil {
			// 落盘失败不阻断：内存里已经生效，重启后回退内置页。
			warnings = append(warnings, "模板已生效，但写入文件失败（重启后会丢失）："+err.Error())
		} else {
			next.BlockPage.File = m.File
			warnings = append(warnings, "模板已写入 "+m.File)
		}
	}
	if html == "" {
		warnings = append(warnings, "已恢复为内置拦截页")
	}
	return &next, warnings, nil
}

// SetBlockPageOptions 改拦截页的外观与文案参数。
type SetBlockPageOptions struct {
	Status      int
	Branding    *bool
	ProductName string
	ProductURL  string
	Contact     string
	Title       string
}

func (m SetBlockPageOptions) Name() string { return "block_page.set_options" }

func (m SetBlockPageOptions) Apply(cur *State) (*State, []string, error) {
	opts := cur.BlockPage.Options
	if m.Status != 0 {
		if m.Status < 100 || m.Status > 599 {
			return nil, nil, fmt.Errorf("status=%d 不是合法 HTTP 状态码", m.Status)
		}
		// 拦截页状态码用 2xx/3xx 没有意义，也容易把"被拦"伪装成"成功"，
		// 那会让调用方以为请求成功了。
		if m.Status < 400 {
			return nil, nil, fmt.Errorf("拦截页状态码必须 >= 400（当前 %d）；用 2xx 会让调用方以为请求成功", m.Status)
		}
		opts.Status = m.Status
	}
	if m.Branding != nil {
		opts.Branding = *m.Branding
	}
	if m.ProductName != "" {
		opts.ProductName = m.ProductName
	}
	opts.ProductURL = m.ProductURL
	opts.Contact = m.Contact
	if m.Title != "" {
		opts.Title = m.Title
	}
	opts.CustomHTML = cur.BlockPage.CustomHTML

	r := blockpage.New(opts)
	if r.CustomError() != "" {
		return nil, nil, fmt.Errorf("模板编译失败：%s", r.CustomError())
	}

	next := *cur
	next.BlockPage = BlockPageState{
		Options:    opts,
		CustomHTML: cur.BlockPage.CustomHTML,
		File:       cur.BlockPage.File,
		Renderer:   r,
	}
	next.Reason = "控制台修改拦截页参数"
	return &next, nil, nil
}

// PreviewBlockPageHTML 只渲染一个预览，不产生状态变更。
//
// 控制台里"改一个字看一次效果"走这里：它连 State 都不动。
func PreviewBlockPageHTML(cur *State, html string, sample SampleRequest) (string, error) {
	opts := cur.BlockPage.Options
	opts.CustomHTML = html
	r := blockpage.New(opts)
	if r.CustomError() != "" {
		return "", fmt.Errorf("模板编译失败：%s", r.CustomError())
	}
	d := blockpage.Data{
		Status:        opts.Status,
		StatusText:    statusText(opts.Status),
		TxID:          "01J8ZK3M4N5P7Q8R9S0T",
		Time:          time.Now().Format("2006-01-02 15:04:05"),
		Method:        orDefault(sample.Method, "GET"),
		Host:          orDefault(sample.Host, "shop.example.com"),
		Path:          orDefault(sample.Path, "/product/1234"),
		Category:      orDefault(sample.Category, "sqli"),
		CategoryLabel: blockpage.CategoryLabel(orDefault(sample.Category, "sqli")),
		ClientIP:      orDefault(sample.ClientIP, "203.0.113.7"),
		Branding:      opts.Branding,
		ProductName:   opts.ProductName,
		ProductURL:    opts.ProductURL,
		Contact:       opts.Contact,
		Version:       opts.Version,
		Title:         opts.Title,
	}
	return string(r.RenderHTML(d)), nil
}

// SampleRequest 是预览用的样例请求。
type SampleRequest struct {
	Method, Host, Path, Category, ClientIP string
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func statusText(code int) string {
	if s := http.StatusText(code); s != "" {
		return s
	}
	return "Blocked"
}

// validateTemplatePath 校验模板落盘路径，返回清理后的相对路径。
//
// **路径必须收口**。`block_page.file` 是控制台可以改的字段，
// 而它决定"往哪个路径写文件" —— 不收口就等于"一个会话 + 一个字段 =
// 在服务器上任意位置写文件"。模板属于配置，只允许相对路径、且不能跳出所在目录。
//
// 注意 Windows：`/etc/passwd` 这种"根路径但无盘符"的形式 `filepath.IsAbs` 返回 false，
// 但它照样会落到 `C:\etc\passwd` —— 所以必须额外挡掉前导分隔符。
//
// 单独抽成纯函数是为了**能安全地单测**：写路径的测试绝不该真去碰 `/etc/passwd`。
func validateTemplatePath(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("未指定文件路径")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") || strings.HasPrefix(name, `\`) {
		return "", fmt.Errorf("模板路径必须是相对路径（相对配置文件目录），不接受绝对路径：%q", name)
	}
	// Windows 上挡住盘符形式（`C:foo` 是"盘符相对"，会跳出当前目录）
	if vol := filepath.VolumeName(name); vol != "" {
		return "", fmt.Errorf("模板路径不能带盘符：%q", name)
	}
	clean := filepath.Clean(name)
	if clean == ".." || clean == "." ||
		strings.HasPrefix(clean, ".."+string(filepath.Separator)) ||
		strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("模板路径不能跳出配置目录：%q", name)
	}
	return clean, nil
}

func writeTemplateFile(name, html string) error {
	clean, err := validateTemplatePath(name)
	if err != nil {
		return err
	}
	name = clean

	dir := filepath.Dir(name)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	// 先写临时文件再改名：避免写一半留下残缺模板，下次启动读到坏文件。
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, []byte(html), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}

// mergeDisable 合并"当前已停用"与"本次额外停用"（后者覆盖前者即可，都是集合）。
func mergeDisable(cur map[string]bool, extra []string) map[string]bool {
	if len(extra) == 0 {
		return cur
	}
	out := make(map[string]bool, len(cur)+len(extra))
	for k, v := range cur {
		out[k] = v
	}
	for _, id := range extra {
		if id = strings.TrimSpace(id); id != "" {
			out[id] = true
		}
	}
	return out
}

// ---------------------------------------------------------------- 规则

// ReloadRules 从磁盘重载规则集（带上控制台的停用集合）。
type ReloadRules struct {
	Dir   string
	Files []string
	// Disable 是"这次加载额外停用这些规则 ID"。
	//
	// 用途是控制台的**预演**："停用这几条之后还剩多少条、会不会把某条链打断" ——
	// 原先控制台收了这个字段却从不使用，
	// 于是预演结果与"真的停用之后"不一致，运维看到的数字是错的。
	Disable []string
}

func (m ReloadRules) Name() string { return "rules.reload" }

func (m ReloadRules) Apply(cur *State) (*State, []string, error) {
	opts := rules.DefaultOptions()
	// 重载时**必须保留停用集合**，否则控制台里停用的规则会"自动复活"。
	opts.DisableIDs = mergeDisable(cur.DisabledRules, m.Disable)
	opts.FileBase = m.Dir

	var (
		rs  *rules.RuleSet
		err error
	)
	if len(m.Files) > 0 {
		var files []string
		for _, pat := range m.Files {
			matches, gerr := filepath.Glob(filepath.Join(m.Dir, pat))
			if gerr != nil {
				return nil, nil, fmt.Errorf("规则文件通配 %q 无效：%w", pat, gerr)
			}
			files = append(files, matches...)
		}
		if len(files) == 0 {
			return nil, nil, fmt.Errorf("目录 %s 下没有匹配 %v 的规则文件", m.Dir, m.Files)
		}
		rs, err = rules.LoadFiles(opts, files)
	} else {
		rs, err = rules.LoadDir(opts, m.Dir, []string{"*.yaml", "*.yml"})
	}
	if err != nil {
		// 自测没过也走这里：**整批拒绝**，旧规则集继续用。
		return nil, nil, err
	}

	st := rs.Stats()
	next := *cur
	next.RuleSet = rs
	next.Reason = "重载规则集"

	var warnings []string
	warnings = append(warnings, fmt.Sprintf("已加载 %d 条规则（启用 %d），变换链 %d 条",
		st.Rules, st.Enabled, st.Chains))
	warnings = append(warnings, st.Warnings...)
	return &next, warnings, nil
}

// SetRuleEnabled 停用/启用单条规则。
//
// 实现方式是重载规则集并带上停用集合 —— 不改规则文件。
// 理由：规则文件是版本化产物，控制台点一下就把 YAML 改掉会让文件与 git 历史对不上。
type SetRuleEnabled struct {
	ID      string
	Enabled bool
	Dir     string
	Files   []string
}

func (m SetRuleEnabled) Name() string {
	if m.Enabled {
		return "rules.enable"
	}
	return "rules.disable"
}

func (m SetRuleEnabled) Apply(cur *State) (*State, []string, error) {
	if strings.TrimSpace(m.ID) == "" {
		return nil, nil, fmt.Errorf("缺少规则 ID")
	}
	if cur.RuleSet != nil {
		if _, ok := cur.RuleSet.Rule(m.ID); !ok {
			return nil, nil, fmt.Errorf("规则 %s 不存在", m.ID)
		}
	}
	disabled := map[string]bool{}
	for k, v := range cur.DisabledRules {
		disabled[k] = v
	}
	if m.Enabled {
		delete(disabled, m.ID)
	} else {
		disabled[m.ID] = true
	}

	sub := ReloadRules{Dir: m.Dir, Files: m.Files}
	// 让重载看到新的停用集合
	tmp := *cur
	tmp.DisabledRules = disabled
	next, warnings, err := sub.Apply(&tmp)
	if err != nil {
		return nil, nil, err
	}
	next.DisabledRules = disabled
	if m.Enabled {
		next.Reason = "启用规则 " + m.ID
	} else {
		next.Reason = "停用规则 " + m.ID
	}
	return next, warnings, nil
}

// ---------------------------------------------------------------- 限速

// SetRateLimit 改限速参数。
type SetRateLimit struct {
	Enabled      *bool
	RPS          *float64
	Burst        *float64
	BanAfterHits *int
	BanWindow    *time.Duration
	BanDuration  *time.Duration
	Whitelist    []string
}

func (m SetRateLimit) Name() string { return "ratelimit.set" }

func (m SetRateLimit) Apply(cur *State) (*State, []string, error) {
	st := cur.RateLimit
	if m.Enabled != nil {
		st.Enabled = *m.Enabled
	}
	if m.RPS != nil {
		if *m.RPS < 0 {
			return nil, nil, fmt.Errorf("rps 不能为负")
		}
		st.RPS = *m.RPS
	}
	if m.Burst != nil {
		if *m.Burst < 1 {
			return nil, nil, fmt.Errorf("burst 至少为 1")
		}
		st.Burst = *m.Burst
	}
	if m.BanAfterHits != nil {
		if *m.BanAfterHits < 0 {
			return nil, nil, fmt.Errorf("ban_after_hits 不能为负")
		}
		st.BanAfterHits = *m.BanAfterHits
	}
	if m.BanWindow != nil {
		if *m.BanWindow <= 0 {
			return nil, nil, fmt.Errorf("ban_window 必须为正")
		}
		st.BanWindow = *m.BanWindow
	}
	if m.BanDuration != nil {
		if *m.BanDuration <= 0 {
			return nil, nil, fmt.Errorf("ban_duration 必须为正")
		}
		st.BanDuration = *m.BanDuration
	}
	if m.Whitelist != nil {
		st.Whitelist = append([]string(nil), m.Whitelist...)
	}

	next := *cur
	next.RateLimit = st
	next.Reason = "控制台修改限速"
	return &next, nil, nil
}

// ---------------------------------------------------------------- 备份恢复

// SetRulesFromSource 用一段 YAML 直接替换规则集（**不落盘**）。
//
// 用途：备份恢复。刻意不写回 rules/ 目录 —— 那会覆盖运维的规则文件，
// 而"恢复"是个容易点错的操作，出错代价应当是"重启后回到磁盘状态"
// 而不是"磁盘上的规则被覆盖了"。
type SetRulesFromSource struct {
	SourceName string
	YAML       string
	// Disable 同上：预演时额外停用的规则 ID。
	Disable []string
}

func (m SetRulesFromSource) Name() string { return "rules.restore_from_source" }

func (m SetRulesFromSource) Apply(cur *State) (*State, []string, error) {
	if strings.TrimSpace(m.YAML) == "" {
		return nil, nil, fmt.Errorf("规则内容为空")
	}
	name := m.SourceName
	if name == "" {
		name = "restored.yaml"
	}
	opts := rules.DefaultOptions()
	opts.DisableIDs = mergeDisable(cur.DisabledRules, m.Disable)
	rs, err := rules.LoadSource(opts, name, []byte(m.YAML))
	if err != nil {
		return nil, nil, err
	}
	st := rs.Stats()
	next := *cur
	next.RuleSet = rs
	next.Reason = "从备份恢复规则集"
	return &next, []string{fmt.Sprintf("已恢复：%d 条规则（启用 %d），变换链 %d 条", st.Rules, st.Enabled, st.Chains)}, nil
}

// RestoreBlockPage 从备份恢复拦截页。
type RestoreBlockPage struct {
	HTML    string
	Options blockpage.Options
	File    string
}

func (m RestoreBlockPage) Name() string { return "block_page.restore" }

func (m RestoreBlockPage) Apply(cur *State) (*State, []string, error) {
	opts := m.Options
	opts.CustomHTML = m.HTML
	if opts.Status == 0 {
		opts.Status = cur.BlockPage.Options.Status
	}
	if opts.ProductName == "" {
		opts.ProductName = cur.BlockPage.Options.ProductName
	}
	r := blockpage.New(opts)
	if r.CustomError() != "" {
		return nil, nil, fmt.Errorf("拦截页模板编译失败：%s", r.CustomError())
	}
	next := *cur
	next.BlockPage = BlockPageState{Options: opts, CustomHTML: m.HTML, File: m.File, Renderer: r}
	next.Reason = "从备份恢复拦截页"
	return &next, nil, nil
}

// ---------------------------------------------------------------- 例外

// SetExceptions 整体替换控制台维护的例外列表。
type SetExceptions struct {
	List []*rules.Exception
}

func (m SetExceptions) Name() string { return "exceptions.set" }

func (m SetExceptions) Apply(cur *State) (*State, []string, error) {
	seen := map[string]bool{}
	for _, ex := range m.List {
		if ex == nil {
			return nil, nil, fmt.Errorf("例外列表里有空条目")
		}
		if seen[ex.ID] {
			return nil, nil, fmt.Errorf("例外 ID %s 重复", ex.ID)
		}
		seen[ex.ID] = true
	}
	next := *cur
	next.Exceptions = m.List
	next.Reason = "控制台更新例外"
	warn := []string{fmt.Sprintf("当前共 %d 条例外（控制台维护）", len(m.List))}
	for _, ex := range m.List {
		if time.Until(ex.Expires) < 72*time.Hour {
			warn = append(warn, fmt.Sprintf("例外 %s 将在 %s 过期", ex.ID, ex.Expires.Format("2006-01-02")))
		}
	}
	return &next, warn, nil
}

// ---------------------------------------------------------------- IP 名单

// SetIPLists 更新 IP 允许/拒绝名单。
type SetIPLists struct {
	Allow      []string
	Deny       []string
	DenyStatus int
}

func (m SetIPLists) Name() string { return "iplists.set" }

func (m SetIPLists) Apply(cur *State) (*State, []string, error) {
	// 逐条校验 CIDR/IP：名单写错就是"把攻击者放进来"或"把用户挡在外面"，
	// 绝不允许静默忽略坏条目。
	validate := func(list []string, kind string) error {
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" {
				return fmt.Errorf("%s 名单里有空条目", kind)
			}
			if _, err := netip.ParsePrefix(s); err == nil {
				continue
			}
			if _, err := netip.ParseAddr(s); err == nil {
				continue
			}
			return fmt.Errorf("%s 名单里的 %q 既不是 CIDR 也不是 IP", kind, s)
		}
		return nil
	}
	if err := validate(m.Allow, "允许"); err != nil {
		return nil, nil, err
	}
	if err := validate(m.Deny, "拒绝"); err != nil {
		return nil, nil, err
	}
	// 同一个地址同时出现在两个名单里：拒绝优先，但要提醒 —— 这通常是配置事故。
	var warn []string
	for _, a := range m.Allow {
		for _, d := range m.Deny {
			if strings.TrimSpace(a) == strings.TrimSpace(d) {
				warn = append(warn, fmt.Sprintf("%s 同时在允许与拒绝名单里；按「拒绝优先」处理", a))
			}
		}
	}
	if m.DenyStatus != 0 && (m.DenyStatus < 100 || m.DenyStatus > 599) {
		return nil, nil, fmt.Errorf("deny_status=%d 不是合法 HTTP 状态码", m.DenyStatus)
	}
	next := *cur
	next.IPLists = IPListState{Allow: m.Allow, Deny: m.Deny, DenyStatus: m.DenyStatus}
	next.Reason = "控制台更新 IP 名单"
	warn = append(warn, fmt.Sprintf("允许 %d 条（跳过检测与限速）、拒绝 %d 条", len(m.Allow), len(m.Deny)))
	return &next, warn, nil
}

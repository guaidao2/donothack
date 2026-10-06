package control

import (
	"fmt"
	"net/http"
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

func writeTemplateFile(name, html string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("未指定文件路径")
	}
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

// ---------------------------------------------------------------- 规则

// ReloadRules 从磁盘重载规则集（带上控制台的停用集合）。
type ReloadRules struct {
	Dir   string
	Files []string
}

func (m ReloadRules) Name() string { return "rules.reload" }

func (m ReloadRules) Apply(cur *State) (*State, []string, error) {
	opts := rules.DefaultOptions()
	// 重载时**必须保留停用集合**，否则控制台里停用的规则会"自动复活"。
	opts.DisableIDs = cur.DisabledRules
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

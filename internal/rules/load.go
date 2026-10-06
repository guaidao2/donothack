package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"donothack/internal/kv"
	"donothack/internal/operator"
	"donothack/internal/transform"
	"donothack/internal/tx"
)

// ---------------------------------------------------------------- YAML 结构

type yamlDoc struct {
	Version    int             `yaml:"version"`
	Meta       yamlMeta        `yaml:"meta"`
	Rules      []yamlRule      `yaml:"rules"`
	Exceptions []yamlException `yaml:"exceptions"`
}

type yamlMeta struct {
	Name     string `yaml:"name"`
	Author   string `yaml:"author"`
	Category string `yaml:"category"`
}

type yamlRule struct {
	ID        string       `yaml:"id"`
	Name      string       `yaml:"name"` // 可选元信息
	Enabled   *bool        `yaml:"enabled"`
	Phase     int          `yaml:"phase"`
	Severity  string       `yaml:"severity"`
	Category  string       `yaml:"category"`
	Score     *int         `yaml:"score"`
	Message   string       `yaml:"message"`
	Desc      string       `yaml:"description"` // 可选元信息
	Tags      []string     `yaml:"tags"`
	Targets   []yamlTarget `yaml:"targets"`
	Transform []string     `yaml:"transforms"`
	Operator  yamlOperator `yaml:"operator"`
	Action    *yamlAction  `yaml:"action"`
	HardBlock bool         `yaml:"hard_block"`
	Chain     bool         `yaml:"chain"`
	Test      yamlTest     `yaml:"test"`
}

type yamlTarget struct {
	Collection string `yaml:"collection"`
	Selector   string `yaml:"selector"`
	Count      bool   `yaml:"count"`
}

type yamlOperator struct {
	Name   string         `yaml:"name"`
	Params map[string]any `yaml:"params"`
}

type yamlAction struct {
	Type     string `yaml:"type"`
	Status   int    `yaml:"status"`
	BanIP    bool   `yaml:"ban_ip"`
	Redirect string `yaml:"redirect_url"`
}

type yamlTest struct {
	Positive []string `yaml:"positive"`
	Negative []string `yaml:"negative"`
}

type yamlException struct {
	ID              string             `yaml:"id"`
	Reason          string             `yaml:"reason"`
	Expires         yamlDate           `yaml:"expires"`
	Match           yamlExceptionMatch `yaml:"match"`
	DisableRules    []string           `yaml:"disable_rules"`
	DisableCategory []string           `yaml:"disable_categories"`
	SkipRateLimit   bool               `yaml:"skip_ratelimit"`
	Mode            string             `yaml:"mode"`
}

type yamlExceptionMatch struct {
	Paths     []string `yaml:"paths"`
	Methods   []string `yaml:"methods"`
	SourceIPs []string `yaml:"source_ips"`
}

// yamlDate 接受 "2027-01-01" 或 RFC3339。
type yamlDate struct{ t time.Time }

func (d *yamlDate) UnmarshalYAML(node *yaml.Node) error {
	s := strings.TrimSpace(node.Value)
	if s == "" {
		return nil
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			d.t = t
			return nil
		}
	}
	return fmt.Errorf("第 %d 行：无法解析日期 %q（示例 2027-01-01）", node.Line, s)
}

// ---------------------------------------------------------------- 加载选项

// Options 是加载参数。
type Options struct {
	// Categories 是允许的类目集合（值是该类目的默认分）。
	// 为 nil 时用 DefaultCategories。
	Categories map[string]int
	MaxRules   int
	// MaxPMPatterns 单条 pm 规则的模式数上限（防止规则集失控）。
	MaxPMPatterns int
	// SelfTest 为 true 时跑规则自带的正负样本，失败则拒绝加载。
	SelfTest bool
	// FileBase 是 pmFromFile / ipMatchFromFile 引用文件的基准目录。
	FileBase string
	// MinLiteralLen 是进预筛的最小字面量长度（更短的不进自动机）。
	MinLiteralLen int
}

// DefaultCategories 是内置类目与默认分（docs/DESIGN.md §10.1）。
func DefaultCategories() map[string]int {
	return map[string]int{
		"sqli":     5,
		"xss":      5,
		"rce":      5,
		"lfi":      5,
		"rfi":      5,
		"webshell": 5,
		"scanner":  3,
		"protocol": 5,
		"upload":   3,
	}
}

// DefaultOptions 返回一组合理默认值。
func DefaultOptions() Options {
	return Options{
		Categories:    DefaultCategories(),
		MaxRules:      20000,
		MaxPMPatterns: 10000,
		SelfTest:      true,
		MinLiteralLen: 3,
	}
}

// LoadDir 加载一个目录下匹配 patterns 的全部规则文件。
func LoadDir(opts Options, dir string, patterns []string) (*RuleSet, error) {
	var files []string
	for _, pat := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pat))
		if err != nil {
			return nil, fmt.Errorf("规则文件通配 %q 无效：%w", pat, err)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("目录 %s 下没有匹配 %v 的规则文件", dir, patterns)
	}
	return LoadFiles(opts, files)
}

// LoadFiles 加载并编译指定的规则文件。
func LoadFiles(opts Options, files []string) (*RuleSet, error) {
	if opts.Categories == nil {
		opts.Categories = DefaultCategories()
	}
	if opts.MaxRules <= 0 {
		opts.MaxRules = 20000
	}
	if opts.MaxPMPatterns <= 0 {
		opts.MaxPMPatterns = 10000
	}
	if opts.MinLiteralLen <= 0 {
		opts.MinLiteralLen = 3
	}
	if opts.FileBase == "" {
		if len(files) > 0 {
			opts.FileBase = filepath.Dir(files[0])
		} else {
			opts.FileBase = "."
		}
	}
	operator.SetFileBase(opts.FileBase)

	rs := &RuleSet{
		LoadedAt: time.Now(),
		byID:     map[string]*CompiledRule{},
		Source:   strings.Join(files, ", "),
		localities: Stats{
			ByCategory: map[string]int{},
			ByPhase:    map[int]int{},
		},
	}
	rs.localities.Files = len(files)

	errs := &Errors{}
	hasher := sha256.New()
	seenIDs := map[string]SourceRef{}

	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			errs.add("%s：读取失败：%v", file, err)
			continue
		}
		hasher.Write(raw)

		doc, err := parseDoc(file, raw)
		if err != nil {
			errs.add("%v", err)
			continue
		}

		// 例外
		for i, ye := range doc.Exceptions {
			ref := SourceRef{File: file, Index: i + 1}
			ex, err := compileException(ye, ref)
			if err != nil {
				errs.add("%v", err)
				continue
			}
			rs.exceptions = append(rs.exceptions, ex)
		}

		// 规则
		for i, yr := range doc.Rules {
			ref := SourceRef{File: file, Index: i + 1}
			cr, err := compileRule(opts, doc, yr, ref)
			if err != nil {
				errs.add("%v", err)
				continue
			}
			if prev, dup := seenIDs[cr.ID]; dup {
				errs.add("%s：规则 ID %s 与 %s 重复（ID 必须全局唯一，否则审计日志里的历史记录会对不上）",
					ref, cr.ID, prev)
				continue
			}
			seenIDs[cr.ID] = ref

			if len(rs.allRules) >= opts.MaxRules {
				errs.add("%s：规则总数超过上限 %d", ref, opts.MaxRules)
				break
			}
			rs.allRules = append(rs.allRules, cr)
			rs.byID[cr.ID] = cr
			rs.localities.Rules++
			rs.localities.ByCategory[cr.Category]++
			rs.localities.ByPhase[int(cr.Phase)]++
			if cr.Enabled {
				rs.localities.Enabled++
			} else {
				rs.localities.Disabled++
			}
		}
	}

	if err := errs.Err(); err != nil {
		return nil, err
	}

	rs.Version = "sha256:" + hex.EncodeToString(hasher.Sum(nil))[:16]

	// 归一化变换链（去重）
	rs.buildChains()

	// 构建每阶段的索引与预筛
	if err := rs.buildIndex(opts); err != nil {
		return nil, err
	}

	// 自测：正样本必须命中、负样本必须不命中
	if opts.SelfTest {
		if err := rs.SelfTest(); err != nil {
			return nil, err
		}
	}
	return rs, nil
}

func parseDoc(file string, raw []byte) (*yamlDoc, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var doc yamlDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s：YAML 解析失败：%w", file, err)
	}
	if doc.Version != 1 {
		return nil, fmt.Errorf("%s：version 必须是 1（当前 %d）", file, doc.Version)
	}
	if strings.TrimSpace(doc.Meta.Name) == "" {
		return nil, fmt.Errorf("%s：meta.name 必填", file)
	}
	if len(doc.Rules) == 0 && len(doc.Exceptions) == 0 {
		return nil, fmt.Errorf("%s：既没有 rules 也没有 exceptions", file)
	}
	return &doc, nil
}

func compileRule(opts Options, doc *yamlDoc, yr yamlRule, ref SourceRef) (*CompiledRule, error) {
	if strings.TrimSpace(yr.ID) == "" {
		return nil, fmt.Errorf("%s：规则缺少 id", ref)
	}
	if yr.Phase != 1 && yr.Phase != 2 {
		if yr.Phase == 3 || yr.Phase == 4 {
			return nil, fmt.Errorf("%s：规则 %s 用了 phase %d（响应侧）。本轮只做请求侧检测，响应规则会永远不生效，所以直接拒绝",
				ref, yr.ID, yr.Phase)
		}
		return nil, fmt.Errorf("%s：规则 %s 的 phase=%d 非法（只支持 1 请求头、2 请求体）", ref, yr.ID, yr.Phase)
	}
	sev, ok := tx.ParseSeverity(strings.ToLower(strings.TrimSpace(yr.Severity)))
	if !ok {
		return nil, fmt.Errorf("%s：规则 %s 的 severity=%q 非法（info|low|medium|high|critical）", ref, yr.ID, yr.Severity)
	}
	category := strings.TrimSpace(yr.Category)
	if category == "" {
		category = strings.TrimSpace(doc.Meta.Category)
	}
	if category == "" {
		return nil, fmt.Errorf("%s：规则 %s 缺少 category", ref, yr.ID)
	}
	defScore, ok := opts.Categories[category]
	if !ok {
		return nil, fmt.Errorf("%s：规则 %s 的 category=%q 不在允许的类目里（可用：%s）",
			ref, yr.ID, category, strings.Join(sortedKeys(opts.Categories), " | "))
	}
	score := defScore
	if yr.Score != nil {
		score = *yr.Score
	}
	if score < 0 {
		return nil, fmt.Errorf("%s：规则 %s 的 score 不能为负", ref, yr.ID)
	}

	if len(yr.Targets) == 0 {
		return nil, fmt.Errorf("%s：规则 %s 缺少 targets", ref, yr.ID)
	}
	plans := make([]VarPlan, 0, len(yr.Targets))
	for _, t := range yr.Targets {
		plan, err := compileTarget(t, ref, yr.ID)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}

	// 变换链
	fns := make([]TransformFn, 0, len(yr.Transform))
	for _, name := range yr.Transform {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		fn, ok := transform.Lookup(name)
		if !ok {
			hint := ""
			if s := transform.Suggestion(name); s != "" {
				hint = fmt.Sprintf("（是否想写 %q？）", s)
			}
			return nil, fmt.Errorf("%s：规则 %s 引用了未注册的变换 %q%s；可用变换见 docs/RULES.md §6",
				ref, yr.ID, name, hint)
		}
		fns = append(fns, fn)
	}

	// 算子（编译期完成参数校验）
	if strings.TrimSpace(yr.Operator.Name) == "" {
		return nil, fmt.Errorf("%s：规则 %s 缺少 operator.name", ref, yr.ID)
	}
	params := kv.Params(yr.Operator.Params)
	op, err := operator.Compile(yr.Operator.Name, params)
	if err != nil {
		return nil, fmt.Errorf("%s：规则 %s：%w", ref, yr.ID, err)
	}
	if yr.Operator.Name == "pm" || yr.Operator.Name == "pmFromFile" {
		if n := len(params.Strings("patterns")); n > opts.MaxPMPatterns {
			return nil, fmt.Errorf("%s：规则 %s 的 pm 模式数 %d 超过上限 %d", ref, yr.ID, n, opts.MaxPMPatterns)
		}
	}

	enabled := true
	if yr.Enabled != nil {
		enabled = *yr.Enabled
	}
	msg := strings.TrimSpace(yr.Message)
	if msg == "" {
		msg = strings.TrimSpace(yr.Name)
	}
	if msg == "" {
		msg = yr.ID
	}

	cr := &CompiledRule{
		ID:             yr.ID,
		Message:        msg,
		Phase:          tx.Phase(yr.Phase),
		Severity:       sev,
		Category:       category,
		Score:          score,
		Tags:           yr.Tags,
		HardBlock:      yr.HardBlock,
		Chain:          yr.Chain,
		Enabled:        enabled,
		Targets:        plans,
		Transforms:     fns,
		TransformNames: append([]string(nil), yr.Transform...),
		Op:             op,
		OperatorName:   yr.Operator.Name,
		Source:         ref,
		Test:           TestCase{Positive: yr.Test.Positive, Negative: yr.Test.Negative},
		rawParams:      params,
	}

	// 规则自带正负样本是硬性要求：没有样本的规则改了也没人能验证。
	if len(cr.Test.Positive) == 0 || len(cr.Test.Negative) == 0 {
		return nil, fmt.Errorf("%s：规则 %s 必须同时带 test.positive 与 test.negative（负样本至少 2 条）；"+
			"没有样本的规则改动无法验证，见 docs/RULES.md §9.2", ref, yr.ID)
	}
	if len(cr.Test.Negative) < 2 {
		return nil, fmt.Errorf("%s：规则 %s 的负样本只有 %d 条，至少要 2 条（其中一条应是真实业务流量形态）",
			ref, yr.ID, len(cr.Test.Negative))
	}

	cr.Literals, cr.Prefilterable = extractLiterals(cr, opts.MinLiteralLen)
	return cr, nil
}

func compileTarget(t yamlTarget, ref SourceRef, ruleID string) (VarPlan, error) {
	col := strings.ToUpper(strings.TrimSpace(t.Collection))
	if col == "" {
		return VarPlan{}, fmt.Errorf("%s：规则 %s 的 target 缺少 collection", ref, ruleID)
	}
	if strings.HasPrefix(col, "RESPONSE") {
		return VarPlan{}, fmt.Errorf("%s：规则 %s 用了响应侧集合 %s —— 本轮不实现响应检测，"+
			"这样的规则永远不会生效，所以直接在加载期拒绝", ref, ruleID, col)
	}
	if !knownCollection(col) {
		return VarPlan{}, fmt.Errorf("%s：规则 %s 用了未知集合 %s（可用集合见 docs/RULES.md §5.1）", ref, ruleID, col)
	}
	plan := VarPlan{Collection: col, Selector: strings.TrimSpace(t.Selector), Count: t.Count}

	sel := plan.Selector
	switch {
	case sel == "":
	case strings.HasPrefix(sel, "!") && len(sel) > 1:
		plan.Exclude = append(plan.Exclude, sel[1:])
	case len(sel) > 2 && strings.HasPrefix(sel, "/") && strings.HasSuffix(sel, "/"):
		re, err := regexp.Compile(sel[1 : len(sel)-1])
		if err != nil {
			return VarPlan{}, fmt.Errorf("%s：规则 %s 的 selector 正则 %q 无法编译：%w", ref, ruleID, sel, err)
		}
		plan.SelectorRe = re
	}
	return plan, nil
}

var knownCollections = map[string]bool{
	"ARGS": true, "ARGS_GET": true, "ARGS_POST": true, "ARGS_JSON": true, "ARGS_XML": true,
	"ARGS_NAMES":            true,
	"REQUEST_URI":           true,
	"REQUEST_PATH":          true,
	"REQUEST_METHOD":        true,
	"REQUEST_PROTOCOL":      true,
	"REQUEST_HEADERS":       true,
	"REQUEST_HEADERS_NAMES": true,
	"REQUEST_COOKIES":       true,
	"REQUEST_COOKIES_NAMES": true,
	"REQUEST_BODY":          true,
	"FILES":                 true,
	"FILES_NAMES":           true,
	"FILES_SIZES":           true,
	"FILES_MAGIC":           true,
	"REMOTE_ADDR":           true,
	"ARGS_COUNT":            true,
	"REQUEST_URI_LENGTH":    true,
	"REQUEST_BODY_LENGTH":   true,
}

func knownCollection(c string) bool { return knownCollections[c] }

func compileException(ye yamlException, ref SourceRef) (*Exception, error) {
	if strings.TrimSpace(ye.ID) == "" {
		return nil, fmt.Errorf("%s：例外缺少 id", ref)
	}
	if strings.TrimSpace(ye.Reason) == "" {
		return nil, fmt.Errorf("%s：例外 %s 缺少 reason。例外必须写清为什么放行，否则半年后没人敢删它", ref, ye.ID)
	}
	if ye.Expires.t.IsZero() {
		return nil, fmt.Errorf("%s：例外 %s 缺少 expires。例外没有到期时间就会变成永久后门", ref, ye.ID)
	}
	if ye.Expires.t.Sub(time.Now()) > 366*24*time.Hour {
		return nil, fmt.Errorf("%s：例外 %s 的 expires 超过一年（%s）。长期例外应当走正式规则调整",
			ref, ye.ID, ye.Expires.t.Format("2006-01-02"))
	}
	mode := ye.Mode
	if mode == "" {
		mode = "skip"
	}
	if mode != "skip" && mode != "detect_only" {
		return nil, fmt.Errorf("%s：例外 %s 的 mode=%q 非法（skip | detect_only）", ref, ye.ID, mode)
	}
	ex := &Exception{
		ID:              ye.ID,
		Reason:          ye.Reason,
		Expires:         ye.Expires.t,
		Paths:           ye.Match.Paths,
		Methods:         ye.Match.Methods,
		SourceIPs:       ye.Match.SourceIPs,
		DisableRules:    ye.DisableRules,
		DisableCategory: ye.DisableCategory,
		SkipRateLimit:   ye.SkipRateLimit,
		Mode:            mode,
		Source:          ref,
	}
	for _, p := range ex.Paths {
		if !strings.HasPrefix(p, "/") {
			return nil, fmt.Errorf("%s：例外 %s 的 paths 里的 %q 必须以 / 开头", ref, ye.ID, p)
		}
	}
	return ex, nil
}

// buildChains 把全部规则的变换链归一化去重。
//
// 这是低配下的关键优化：300 条规则通常只有 5~10 条不同的链，
// 运行期每个不同链只算一次，而不是每条规则各算一遍
// （docs/PERFORMANCE.md §4）。
func (rs *RuleSet) buildChains() {
	index := map[string]int{}
	for _, r := range rs.allRules {
		if !r.Enabled {
			continue
		}
		key := strings.Join(r.TransformNames, ",")
		id, ok := index[key]
		if !ok {
			id = len(rs.chains)
			index[key] = id
			rs.chains = append(rs.chains, ChainInfo{Names: key, Fns: r.Transforms})
		}
		r.ChainID = id
		rs.chains[id].Rules++
	}
	rs.localities.Chains = len(rs.chains)

	// 去重后的链可能有多条内容相同但名字不同（例如前后有空的项），
	// 这里只按名字归并，保留最简形式。
	for i := range rs.chains {
		if rs.chains[i].Names == "" {
			rs.chains[i].Names = "(无变换)"
		}
	}
}

// extractLiterals 从算子里提取可以进预筛的字面量。
//
// 提取不到字面量的规则（如纯 entropy、validateByteRange）必须每请求都跑，
// 它们数量占比是**规则集质量**的硬指标，因此要统计并告警。
func extractLiterals(r *CompiledRule, minLen int) ([][]byte, bool) {
	var lits [][]byte
	params := r.opParams()
	switch r.OperatorName {
	case "contains", "eq", "eqIgnoreCase", "equals":
		if v := params.String("value"); v != "" {
			lits = append(lits, []byte(v))
		}
	case "containsAny":
		for _, v := range params.Strings("values") {
			lits = append(lits, []byte(v))
		}
	case "startsWith", "endsWith":
		if v := params.String("value"); v != "" {
			lits = append(lits, []byte(v))
		}
	case "pm":
		for _, v := range params.Strings("patterns") {
			lits = append(lits, []byte(v))
		}
	case "regex", "regexCaseInsensitive":
		if re, err := regexp.Compile(params.String("pattern")); err == nil {
			if prefix, _ := re.LiteralPrefix(); len(prefix) > 0 {
				lits = append(lits, []byte(prefix))
			}
		}
	default:
		// 语义算子不看字面量，必须每请求评估
		return nil, false
	}

	kept := make([][]byte, 0, len(lits))
	for _, l := range lits {
		if len(l) < minLen {
			// 太短的字面量（如 "a"、".."）会让自动机几乎在每个输入上命中，
			// 预筛等于失效，还不如不进自动机。
			continue
		}
		kept = append(kept, l)
	}
	if len(kept) == 0 {
		return nil, false
	}
	return kept, true
}

// opParams 重新取出算子的原始参数（编译后只保留实例，字面量提取需要原始值）。
func (r *CompiledRule) opParams() kv.Params {
	return r.rawParams
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

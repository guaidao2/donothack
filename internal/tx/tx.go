// Package tx 定义贯穿一次请求-响应的事务对象与其上的核心抽象。
//
// 它是依赖图的最底层：不依赖任何其它内部包，谁都可以依赖它。
//
// 关键设计：Params 是**arena 式**的（一段可复用的字节池 + 定长索引），
// 而不是 map[string][]string。原因有两个：
//  1. 热路径零分配是硬门禁 —— map 与 string 转换都会分配，而每个请求都要解析参数。
//  2. HPP（HTTP 参数污染，同名参数多次出现）在攻击里很常见：
//     只读第一个取值的过滤器会漏，取最后一个取值的框架会执行。
//     所以同名参数的**所有**取值都必须保留，查询时用线性扫描（参数通常只有几个，
//     cache 友好，且完全不分配）。
package tx

import (
	"strconv"
	"time"
)

// Verdict 是最终裁决。
type Verdict int

const (
	VerdictPass Verdict = iota
	VerdictLog
	VerdictBlock
	VerdictChallenge
	VerdictTarpit
	VerdictDrop
)

func (v Verdict) String() string {
	switch v {
	case VerdictPass:
		return "pass"
	case VerdictLog:
		return "log"
	case VerdictBlock:
		return "block"
	case VerdictChallenge:
		return "challenge"
	case VerdictTarpit:
		return "tarpit"
	case VerdictDrop:
		return "drop"
	default:
		return "verdict(" + strconv.Itoa(int(v)) + ")"
	}
}

// Phase 是流水线阶段。
//
// 编号沿用 ModSecurity 的习惯：1 请求头 / 2 请求体 / 5 收尾。
// 3、4 是响应侧，本轮不做（见 docs/DESIGN.md §12），保留编号以便将来占用。
type Phase int

const (
	PhaseRequestHeaders Phase = 1
	PhaseRequestBody    Phase = 2
	PhaseResponseHeader Phase = 3 // 保留未实现
	PhaseResponseBody   Phase = 4 // 保留未实现
	PhaseLogging        Phase = 5
)

func (p Phase) String() string {
	switch p {
	case PhaseRequestHeaders:
		return "phase1"
	case PhaseRequestBody:
		return "phase2"
	case PhaseResponseHeader:
		return "phase3"
	case PhaseResponseBody:
		return "phase4"
	case PhaseLogging:
		return "phase5"
	default:
		return "phase(" + strconv.Itoa(int(p)) + ")"
	}
}

// Severity 是规则严重度。
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevLow:
		return "low"
	case SevMedium:
		return "medium"
	case SevHigh:
		return "high"
	case SevCritical:
		return "critical"
	default:
		return "severity(" + strconv.Itoa(int(s)) + ")"
	}
}

// ParseSeverity 解析规则里的严重度字符串。
func ParseSeverity(s string) (Severity, bool) {
	switch s {
	case "info":
		return SevInfo, true
	case "low":
		return SevLow, true
	case "medium":
		return SevMedium, true
	case "high":
		return SevHigh, true
	case "critical":
		return SevCritical, true
	default:
		return SevInfo, false
	}
}

// Event 是一次规则命中。
//
// 审计里**不记录 payload 原文**（默认），只记目标名、算子、命中长度与指纹描述 ——
// 审计日志本身不该成为敏感数据泄露点，也不该被 payload 撑爆。
type Event struct {
	RuleID     string    `json:"rule_id"`
	Phase      Phase     `json:"phase"`
	Category   string    `json:"category"`
	Severity   Severity  `json:"severity"`
	Score      int       `json:"score"`
	Target     string    `json:"target"`   // 例如 ARGS:user
	Operator   string    `json:"operator"` // 例如 detectSQLi
	Detail     string    `json:"detail"`   // 人类可读的命中说明（不含 payload）
	MatchedLen int       `json:"matched_len"`
	Truncated  bool      `json:"truncated,omitempty"`
	HardBlock  bool      `json:"hard_block,omitempty"`
	At         time.Time `json:"at"`
}

// CatScore 是单个类目的累计分。
type CatScore struct {
	Category string
	Score    int
}

// Score 是按类目累计的异常分。
//
// 用定长数组 + 线性查找，而不是 map：类目只有十来个，而每个请求都要加分，
// map 的哈希与扩容在有检测的路径上是纯开销。
type Score struct {
	Total int
	byCat [16]CatScore
	nCat  int
}

// Add 给某个类目加分。
func (s *Score) Add(category string, delta int) {
	s.Total += delta
	for i := 0; i < s.nCat; i++ {
		if s.byCat[i].Category == category {
			s.byCat[i].Score += delta
			return
		}
	}
	if s.nCat < len(s.byCat) {
		s.byCat[s.nCat] = CatScore{Category: category, Score: delta}
		s.nCat++
	}
}

// Get 返回某个类目的累计分。
func (s *Score) Get(category string) int {
	for i := 0; i < s.nCat; i++ {
		if s.byCat[i].Category == category {
			return s.byCat[i].Score
		}
	}
	return 0
}

// Each 遍历已计分的类目。
func (s *Score) Each(fn func(category string, score int) bool) {
	for i := 0; i < s.nCat; i++ {
		if !fn(s.byCat[i].Category, s.byCat[i].Score) {
			return
		}
	}
}

// Reset 清空计分，供对象池复用。
func (s *Score) Reset() {
	s.Total = 0
	for i := 0; i < s.nCat; i++ {
		s.byCat[i] = CatScore{}
	}
	s.nCat = 0
}

// Param 是参数在 arena 里的位置。
type Param struct {
	KeyOff uint32
	KeyLen uint32
	ValOff uint32
	ValLen uint32
}

// Params 是一组参数的 arena 视图。
//
// 复用方式：Reset 后继续 Add，底层切片容量会保留，因此稳态下不分配。
type Params struct {
	arena     []byte
	items     []Param
	truncated bool // 因为上限而丢弃过参数
	tooLong   bool // 因为上限而截断过值
}

// Reset 清空内容但保留容量。
func (p *Params) Reset() {
	p.arena = p.arena[:0]
	p.items = p.items[:0]
	p.truncated = false
	p.tooLong = false
}

// Len 返回参数个数（含同名重复）。
func (p *Params) Len() int { return len(p.items) }

// Truncated 报告是否因为参数个数上限丢弃过内容。
func (p *Params) Truncated() bool { return p.truncated }

// TooLong 报告是否因为值长度上限截断过内容。
func (p *Params) TooLong() bool { return p.tooLong }

// Add 追加一个参数。key 与 val 会被复制进 arena。
func (p *Params) Add(key, val []byte) {
	ko := uint32(len(p.arena))
	p.arena = append(p.arena, key...)
	kl := uint32(len(p.arena)) - ko
	vo := uint32(len(p.arena))
	p.arena = append(p.arena, val...)
	vl := uint32(len(p.arena)) - vo
	p.items = append(p.items, Param{KeyOff: ko, KeyLen: kl, ValOff: vo, ValLen: vl})
}

// AddString 是 Add 的字符串便利版本。
func (p *Params) AddString(key, val string) {
	ko := uint32(len(p.arena))
	p.arena = append(p.arena, key...)
	kl := uint32(len(p.arena)) - ko
	vo := uint32(len(p.arena))
	p.arena = append(p.arena, val...)
	vl := uint32(len(p.arena)) - vo
	p.items = append(p.items, Param{KeyOff: ko, KeyLen: kl, ValOff: vo, ValLen: vl})
}

// AddKeyBytes 追加一个参数，键是 []byte、值是 string。
//
// 存在的意义：JSON 展开时路径是 []byte、叶子值是 decoder 给的 string，
// 走这个版本可以避免多一次 []byte(val) 的分配。
func (p *Params) AddKeyBytes(key []byte, val string) {
	ko := uint32(len(p.arena))
	p.arena = append(p.arena, key...)
	kl := uint32(len(p.arena)) - ko
	vo := uint32(len(p.arena))
	p.arena = append(p.arena, val...)
	vl := uint32(len(p.arena)) - vo
	p.items = append(p.items, Param{KeyOff: ko, KeyLen: kl, ValOff: vo, ValLen: vl})
}

// KeyAt 返回第 i 个参数的键。
func (p *Params) KeyAt(i int) []byte {
	it := p.items[i]
	return p.arena[it.KeyOff : it.KeyOff+it.KeyLen]
}

// ValueAt 返回第 i 个参数的值。
func (p *Params) ValueAt(i int) []byte {
	it := p.items[i]
	return p.arena[it.ValOff : it.ValOff+it.ValLen]
}

// Get 返回第一个同名参数的值。
//
// 注意：只取第一个是不安全的（HPP 绕过），规则侧应当用 ForEachValue
// 或 GetAll 把同名参数全部检查一遍。这里保留它是给"确实只要一个值"的场景。
func (p *Params) Get(key string) ([]byte, bool) {
	for i := range p.items {
		if equalBytesString(p.KeyAt(i), key) {
			return p.ValueAt(i), true
		}
	}
	return nil, false
}

// ForEachValue 遍历所有同名参数的值，fn 返回 false 时提前结束。
//
// 这是应对 HPP 的正确姿势：同名参数的每一个取值都要过检测。
func (p *Params) ForEachValue(key string, fn func(val []byte) bool) {
	for i := range p.items {
		if equalBytesString(p.KeyAt(i), key) {
			if !fn(p.ValueAt(i)) {
				return
			}
		}
	}
}

// ForEach 遍历全部参数。fn 返回 false 时提前结束。
func (p *Params) ForEach(fn func(key, val []byte) bool) {
	for i := range p.items {
		if !fn(p.KeyAt(i), p.ValueAt(i)) {
			return
		}
	}
}

// MarkTruncated 记录"因为上限丢弃了参数"。
func (p *Params) MarkTruncated() { p.truncated = true }

// MarkTooLong 记录"因为上限截断了值"。
func (p *Params) MarkTooLong() { p.tooLong = true }

// equalBytesString 比较 []byte 与 string，不产生分配。
func equalBytesString(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

// FileMeta 是一个上传文件的元信息。**不落盘、不整份读入内存**。
type FileMeta struct {
	FieldName   string
	FileName    string
	ContentType string
	Size        int64
	Magic       [16]byte // 头部若干字节，用于 webshell 魔数检测
	MagicLen    int
	Truncated   bool
}

// FileSet 是上传文件集合（按字段名，同名多文件用切片）。
type FileSet map[string][]FileMeta

// Collections 是一次请求拆解后的全部输入来源。
//
// 规则只对着这些集合匹配，不关心值来自 query 还是 JSON body。
// 所有编码绕过（URL 编码、双写、JSON 嵌套、multipart）都由解析层统一吃掉。
type Collections struct {
	// 请求行
	Method  string
	URI     string // RequestURI（含 query），原始形态
	RawPath string // 原始路径（未规范化）—— 必须保留，用于"双形态检测"
	Path    string // 规范化后的路径
	Query   string // 原始 query 串
	Proto   string
	Host    string

	// 参数。同名多值全部保留（HPP）。
	ArgsGet  Params
	ArgsPost Params
	ArgsJSON Params
	ArgsXML  Params
	Args     Params // 以上四者的合并视图（规则默认目标）

	Headers Params
	Cookies Params
	Files   FileSet

	// 请求体
	Body          []byte
	BodyTruncated bool

	// 派生
	RawIP     string
	TxID      string
	StartedAt time.Time
	UserAgent string

	// 解析过程中的异常（fail-open 但必须留痕）
	ParseErrors []string
}

// AddParseError 记录一条解析异常。上限有界，避免被畸形请求刷爆。
func (c *Collections) AddParseError(msg string) {
	const maxErrors = 16
	if len(c.ParseErrors) >= maxErrors {
		return
	}
	c.ParseErrors = append(c.ParseErrors, msg)
}

// Reset 清空集合，供对象池复用。
func (c *Collections) Reset() {
	*c = Collections{
		ArgsGet:     c.ArgsGet,
		ArgsPost:    c.ArgsPost,
		ArgsJSON:    c.ArgsJSON,
		ArgsXML:     c.ArgsXML,
		Args:        c.Args,
		Headers:     c.Headers,
		Cookies:     c.Cookies,
		ParseErrors: c.ParseErrors[:0],
	}
	c.ArgsGet.Reset()
	c.ArgsPost.Reset()
	c.ArgsJSON.Reset()
	c.ArgsXML.Reset()
	c.Args.Reset()
	c.Headers.Reset()
	c.Cookies.Reset()
}

// Transaction 是一次请求-响应事务。
type Transaction struct {
	ID        string
	StartedAt time.Time
	ClientIP  string
	Method    string
	URI       string
	Host      string
	Proto     string
	UserAgent string

	Vars  Collections
	Score Score
}

// Reset 清空事务，供对象池复用。
//
// 注意：必须清掉所有对请求体的引用（Body、arena 里的内容），
// 否则整个 body 无法回收 —— 这是对象池最常见的泄漏点。
func (t *Transaction) Reset() {
	t.ID = ""
	t.StartedAt = time.Time{}
	t.ClientIP = ""
	t.Method = ""
	t.URI = ""
	t.Host = ""
	t.Proto = ""
	t.UserAgent = ""
	t.Vars.Reset()
	t.Score.Reset()
}

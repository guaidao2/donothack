// Package blockpage 生成拦截响应页面。
//
// 设计取舍（这几条都是踩过或想清楚才定的）：
//
//  1. **自包含**：内置页面不含任何外部资源（无字体、无 CDN、无图片、无 JS）。
//     站点被攻击时往往本来就半死不活，拦截页再去加载外部资源只会白屏。
//  2. **绝不回显用户输入**：Host、Path、UA 这些都能被攻击者控制。
//     内置模板只展示白名单里的字段，且全部经 html/template 上下文转义 ——
//     否则我们自己的拦截页就成了反射型 XSS 的输出点。
//  3. **按客户端类型给不同格式**：浏览器给 HTML，API 客户端给 JSON，
//     其余给纯文本。拿 HTML 打 API 会让对方的 JSON 解析直接崩，那比拦截更糟。
//  4. **内容可在控制台自定义**：自定义模板编译失败时**回退到内置页**并留痕，
//     绝不让"运维手滑贴错模板"变成"所有被拦请求 500"。
//  5. **品牌展示可关**：默认展示产品名与版本（有宣传价值），
//     但允许关掉 —— 展示品牌等于告诉攻击者这里有 WAF、是哪一个。
package blockpage

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Options 是渲染器配置。
type Options struct {
	// Status 是拦截状态码（默认 403）。
	Status int
	// Branding 是否展示产品名与版本。
	Branding bool
	// ProductName 产品名（默认 donothack）。
	ProductName string
	// ProductURL 产品主页（可空）。
	ProductURL string
	// Contact 误报申诉渠道（可空，例如安全邮箱或工单地址）。
	Contact string
	// Title 页面标题。
	Title string
	// CustomHTML 是控制台自定义的模板源码；为空则用内置模板。
	CustomHTML string
	// Version 是构建版本，用于页脚与"报障时带上版本"。
	Version string
}

// Data 是模板可用的数据。
//
// **只暴露这些字段**：模板作者能拿到的东西就是这些，不给"原始请求"之类的后门，
// 免得自定义模板里 `{{.Request}}` 一回显就出 XSS。
type Data struct {
	Status        int
	StatusText    string
	TxID          string
	Time          string
	Method        string
	Host          string
	Path          string
	Category      string // 机器可读类目
	CategoryLabel string // 人类可读类目名（中文）
	RuleID        string // 默认不展示给终端用户，自定义模板想用可以用
	ClientIP      string
	RetryAfter    int
	Branding      bool
	ProductName   string
	ProductURL    string
	Contact       string
	Version       string
	Title         string
}

// categoryLabels 是类目到友好名称的映射。
//
// 给终端用户看的页面**不暴露具体规则 ID 与正则**：那等于免费告诉攻击者
// 哪条规则命中、怎么绕。只给类目级别的说明，足够让正常用户明白"为什么被拦"。
var categoryLabels = map[string]string{
	"sqli":      "SQL 注入",
	"xss":       "跨站脚本",
	"rce":       "远程命令执行",
	"lfi":       "路径穿越 / 本地文件包含",
	"rfi":       "远程文件包含 / SSRF",
	"webshell":  "WebShell",
	"scanner":   "扫描器探测",
	"protocol":  "协议异常",
	"upload":    "恶意文件上传",
	"ratelimit": "请求过于频繁",
	"ban":       "临时封禁",
	"exception": "例外规则",
	"":          "安全策略",
}

// CategoryLabel 返回类目的友好名称。
func CategoryLabel(cat string) string {
	if s, ok := categoryLabels[strings.ToLower(strings.TrimSpace(cat))]; ok {
		return s
	}
	return "安全策略"
}

// Renderer 是编译好的页面渲染器。并发安全（模板执行本身是并发安全的）。
type Renderer struct {
	o       Options
	builtin *template.Template
	custom  *template.Template
	// customErr 记录自定义模板编译失败的原因，供 /readyz 与控制台显示。
	customErr string
}

// New 构造渲染器。**自定义模板编译失败不会返回错误**，而是回退到内置模板 ——
// 拦截页是兜底路径，它自己不能成为故障源。失败原因通过 CustomError() 暴露。
func New(o Options) *Renderer {
	if o.Status == 0 {
		o.Status = http.StatusForbidden
	}
	if strings.TrimSpace(o.ProductName) == "" {
		o.ProductName = "donothack"
	}
	if strings.TrimSpace(o.Title) == "" {
		o.Title = "请求已被安全策略拦截"
	}
	r := &Renderer{o: o}
	r.builtin = template.Must(template.New("builtin").Parse(builtinHTML))

	if strings.TrimSpace(o.CustomHTML) != "" {
		t, err := template.New("custom").Parse(o.CustomHTML)
		if err != nil {
			r.customErr = err.Error()
		} else {
			r.custom = t
		}
	}
	return r
}

// CustomError 返回自定义模板的编译错误（空串表示没配或编译通过）。
func (r *Renderer) CustomError() string { return r.customErr }

// UsingCustom 报告当前是否在使用自定义模板。
func (r *Renderer) UsingCustom() bool { return r.custom != nil }

// Options 返回渲染器配置（控制台展示用）。
func (r *Renderer) Options() Options { return r.o }

// NewData 由请求与裁决信息构造模板数据。
func (r *Renderer) NewData(req *http.Request, txID, category, ruleID, clientIP string, status, retryAfter int) Data {
	if status == 0 {
		status = r.o.Status
	}
	d := Data{
		Status:        status,
		StatusText:    http.StatusText(status),
		TxID:          txID,
		Time:          time.Now().Format("2006-01-02 15:04:05"),
		Category:      strings.ToLower(strings.TrimSpace(category)),
		CategoryLabel: CategoryLabel(category),
		RuleID:        ruleID,
		ClientIP:      clientIP,
		RetryAfter:    retryAfter,
		Branding:      r.o.Branding,
		ProductName:   r.o.ProductName,
		ProductURL:    r.o.ProductURL,
		Contact:       r.o.Contact,
		Version:       r.o.Version,
		Title:         r.o.Title,
	}
	if req != nil {
		d.Method = req.Method
		d.Host = req.Host
		// Path 用规范化前的原始路径会回显攻击者构造的串；这里只用我们自己的
		// 解析结果（parser 已规范化过），并且仍然会被模板转义。
		d.Path = req.URL.Path
	}
	return d
}

// RenderHTML 渲染 HTML 页面。
func (r *Renderer) RenderHTML(d Data) []byte {
	var buf bytes.Buffer
	t := r.builtin
	if r.custom != nil {
		t = r.custom
	}
	if err := t.Execute(&buf, d); err != nil {
		// 执行期出错（模板里有非法字段访问等）→ 用内置模板兜底。
		buf.Reset()
		_ = r.builtin.Execute(&buf, d)
	}
	return buf.Bytes()
}

// jsonResponse 是给 API 客户端的结构化响应。
//
// 字段刻意精简：给请求 ID 是为了让用户报障时能对上审计，
// 但不给规则细节与命中位置 —— 那是给攻击者的礼物。
type jsonResponse struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	Status     int    `json:"status"`
	RequestID  string `json:"request_id,omitempty"`
	Category   string `json:"category,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// RenderJSON 渲染 JSON 响应体。
func (r *Renderer) RenderJSON(d Data) []byte {
	msg := "请求已被安全策略拦截"
	if d.Status == http.StatusTooManyRequests {
		msg = "请求过于频繁，请稍后再试"
	}
	body, err := json.Marshal(jsonResponse{
		Error:      "blocked",
		Message:    msg,
		Status:     d.Status,
		RequestID:  d.TxID,
		Category:   d.Category,
		RetryAfter: d.RetryAfter,
	})
	if err != nil {
		return []byte(`{"error":"blocked"}`)
	}
	return append(body, '\n')
}

// RenderText 渲染纯文本响应（给既不接受 HTML 也不接受 JSON 的客户端）。
//
// 这是**洪泛路径**用的最轻格式：被封禁的 IP 每秒可能打进来几千个请求，
// 每次渲染一个模板是纯浪费。文本路径只有一次字符串拼接。
func (r *Renderer) RenderText(d Data) []byte {
	var sb strings.Builder
	sb.Grow(160)
	sb.WriteString("Request blocked")
	if d.CategoryLabel != "" && d.Category != "" {
		sb.WriteString(" [")
		sb.WriteString(d.Category)
		sb.WriteString("]")
	}
	if d.TxID != "" {
		sb.WriteString("\nRequest-ID: ")
		sb.WriteString(d.TxID)
	}
	if d.RetryAfter > 0 {
		sb.WriteString("\nRetry-After: ")
		sb.WriteString(strconv.Itoa(d.RetryAfter))
	}
	if d.Branding {
		sb.WriteString("\n\nProtected by ")
		sb.WriteString(d.ProductName)
		if d.Version != "" {
			sb.WriteString(" ")
			sb.WriteString(d.Version)
		}
	}
	sb.WriteString("\n")
	return []byte(sb.String())
}

// Respond 按客户端偏好写响应。
//
// 判定顺序（先看"客户端要什么"，再看"路径像不像 API"）：
//  1. Accept: application/json 或 X-Requested-With: XMLHttpRequest → JSON
//  2. Accept 里没有 text/html，且路径以 /api/ 开头 → JSON
//  3. Accept 里有 text/html → HTML 页面
//  4. 其余 → 纯文本
func (r *Renderer) Respond(w http.ResponseWriter, req *http.Request, d Data, forceText bool) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if d.TxID != "" {
		h.Set("X-Request-ID", d.TxID)
	}
	if d.RetryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(d.RetryAfter))
	}
	status := d.Status
	if status == 0 {
		status = r.o.Status
	}

	switch {
	case forceText:
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(r.RenderText(d))
	case wantsJSON(req):
		h.Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(r.RenderJSON(d))
	case wantsHTML(req):
		// 页面本身用 no-store，但声明 Vary 让中间缓存别把 JSON 与 HTML 弄混。
		h.Set("Vary", "Accept")
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(r.RenderHTML(d))
	default:
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(r.RenderText(d))
	}
}

func wantsJSON(req *http.Request) bool {
	if req == nil {
		return false
	}
	if strings.EqualFold(req.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	accept := strings.ToLower(req.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") {
		return true
	}
	if strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*") {
		return false
	}
	// 没明确要 HTML，且明显是 API 路径 → JSON
	if strings.HasPrefix(req.URL.Path, "/api/") {
		return true
	}
	return false
}

func wantsHTML(req *http.Request) bool {
	if req == nil {
		return false
	}
	accept := strings.ToLower(req.Header.Get("Accept"))
	if strings.Contains(accept, "text/html") {
		return true
	}
	// 浏览器导航请求通常带 */* 且没有 JSON；给 HTML 更友好。
	// 但 API 路径不给 HTML，避免把 JSON 客户端搞崩。
	if strings.Contains(accept, "*/*") && !strings.HasPrefix(req.URL.Path, "/api/") {
		return true
	}
	return false
}

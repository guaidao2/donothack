package parser

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"donothack/internal/tx"
)

// ParseRequest 把一次请求拆解成规则的输入。
//
// 三条不变量：
//  1. **绝不 panic**：任何解析路径都兜在 recover 里，出问题就 fail-open 放行并记录。
//  2. **绝不静默**：异常全部进 ParseErrors，再由规则阶段记分。
//  3. **双形态保留**：原始路径与规范化路径都留着 —— 攻击者专门利用
//     "WAF 规范化方式和后端不一致"这个差异，只留一个形态就等于漏一半。
func ParseRequest(t *tx.Transaction, r *http.Request, sc *Scratch, lim Limits) {
	t.StartedAt = time.Now()
	t.Method = r.Method
	t.URI = r.RequestURI
	t.Host = r.Host
	t.Proto = r.Proto
	t.UserAgent = r.UserAgent()

	defer func() {
		if rec := recover(); rec != nil {
			t.Vars.AddParseError(fmt.Sprintf("解析 panic：%v", rec))
		}
	}()

	v := &t.Vars
	v.Method = r.Method
	v.URI = r.RequestURI
	v.Proto = r.Proto
	v.Host = r.Host
	v.StartedAt = t.StartedAt
	v.UserAgent = t.UserAgent

	// ---- 路径 ----
	// 注意 StripAbsoluteForm：代理可以发绝对形式（GET http://host/path），
	// 直接当普通路径处理会让规范化结果变成 "http:/host/path"。
	rawPath, rawQuery := SplitURI(r.RequestURI)
	v.RawPath = rawPath
	v.Query = rawQuery
	normalized, truncated := NormalizePathInto(sc.Aux[:0], r.RequestURI, lim.MaxURILength)
	sc.Aux = normalized[:0:cap(normalized)]

	// 快路径：规范化**没有改动**时，路径本来就是 RequestURI 的一个子串，
	// 直接复用那块字符串即可（**零分配**）。只有真的需要改写
	// （百分号解码、折叠 `//`、去除 `..` 等）才建新字符串。
	//
	// 这一步是为了热路径零分配：`string(normalized)` 是每个请求都会发生的一次分配，
	// 而正常业务路径绝大多数根本不需要规范化。
	if !truncated && rawPath != "" && equalStringBytes(rawPath, normalized) {
		v.Path = rawPath
	} else {
		v.Path = string(normalized)
	}
	if truncated {
		v.AddParseError("URI 超过长度上限，已截断")
	}

	// ---- query ----
	if rawQuery != "" {
		ParseQueryInto(&v.ArgsGet, sc, rawQuery, lim)
	} else if r.URL != nil && r.URL.RawQuery != "" {
		// 有些构造出来的请求（测试、内部调用）没有 RequestURI
		v.Query = r.URL.RawQuery
		ParseQueryInto(&v.ArgsGet, sc, v.Query, lim)
	}

	// ---- 请求头 ----
	ParseHeadersInto(&v.Headers, r.Header, sc, lim)
	// Go 的 net/http 会把 Transfer-Encoding 从 Header 移走（放进 r.TransferEncoding），
	// 并在 chunked 时删掉 Content-Length。为了让规则看到"上游将会看到的东西"，
	// 这里按解析后的语义把头补回来 —— 否则针对这两个头的规则是**死规则**，
	// 而"以为在防请求走私其实没有"比没有规则更危险。
	//
	// 注意由此确定的可观测边界：CL+TE 冲突本身在本层已经不可观测（Go 归一化掉了，
	// 所以歧义也传不到上游）。要检测它必须在 net/http 之前抓原始字节，见 。
	if len(r.TransferEncoding) > 0 {
		v.Headers.AddString("transfer-encoding", strings.Join(r.TransferEncoding, ","))
	}
	if r.ContentLength > 0 {
		if _, ok := v.Headers.Get("content-length"); !ok {
			v.Headers.AddString("content-length", strconv.FormatInt(r.ContentLength, 10))
		}
	}
	if ua := r.Header.Get("Cookie"); ua != "" {
		ParseCookiesInto(&v.Cookies, ua, sc, lim)
	}

	// ---- 请求体 ----
	contentType := r.Header.Get("Content-Type")
	mimeType, _ := SplitContentType(contentType)

	// 转发缓冲挂在事务上（生命周期覆盖到转发结束），解析临时缓冲仍用 sc。
	raw, inspect, bodyTruncated, errs := ReadBodyForInspection(r, sc, lim.MaxInspectBody, &t.BodyBuf, &t.InspectBuf)
	for _, e := range errs {
		v.AddParseError(e)
	}
	if raw != nil {
		v.Body = inspect
		v.BodyTruncated = bodyTruncated
		if bodyTruncated {
			v.AddParseError("请求体超过检查上限，只检查了前一段")
		}
		parseBodyInto(v, sc, mimeType, contentType, inspect, lim)
	}

	// ---- 合并视图：规则默认对着 Args 匹配 ----
	//
	// 合并是**防绕过的结构性保证**：如果规则只查 ARGS_GET，
	// 攻击者把 payload 放进 JSON body 就绕过了。
	MergeInto(&v.Args, &v.ArgsGet, lim)
	MergeInto(&v.Args, &v.ArgsPost, lim)
	MergeInto(&v.Args, &v.ArgsJSON, lim)
	MergeInto(&v.Args, &v.ArgsXML, lim)

	// ---- 上限触顶必须上报----
	//
	// 原先各解析函数在触顶时只是 `return`，而 `Truncated()/TooLong()` 只有测试在读 ——
	// 于是"第 1001 个参数、第 10001 个 JSON 叶、第 101 个请求头"在 WAF 眼里**不存在**，
	// 而它们照样被转发给上游。攻击者用 4 KB 的 `a=1&`×1000 填充，就能把 payload
	// 挤出检测视野：**fail-open 却完全静默**，正是包注释里明令禁止的那种。
	//
	// 这里把它们转成 parse_error：由引擎按 protocol 类记分（1 分/条），
	// 控制台能看到、能告警，多条累积也能触发阈值。不做成一碰到就拦 ——
	// 参数多的正常接口不该被误杀，这是**信号**不是判决。
	reportTruncation(v)
}

// reportTruncation 把各集合的"触顶"标志转成 parse_error。
func reportTruncation(v *tx.Collections) {
	type entry struct {
		name string
		p    *tx.Params
	}
	for _, e := range []entry{
		{"query", &v.ArgsGet},
		{"body", &v.ArgsPost},
		{"json", &v.ArgsJSON},
		{"xml", &v.ArgsXML},
		{"headers", &v.Headers},
		{"cookies", &v.Cookies},
		{"合并参数", &v.Args},
	} {
		if e.p == nil {
			continue
		}
		if e.p.Truncated() {
			v.AddParseError("参数数量超过上限（" + e.name +
				"）：超出的部分**未被检测**，但会照常转发给上游")
		}
		if e.p.TooLong() {
			v.AddParseError("参数值超过长度上限（" + e.name +
				"）：超出部分**未被检测**")
		}
	}
}

// parseBodyInto 按 Content-Type 分派请求体解析。
func parseBodyInto(v *tx.Collections, sc *Scratch, mimeType, contentType string, body []byte, lim Limits) {
	if len(body) == 0 {
		return
	}
	switch mimeType {
	case "application/x-www-form-urlencoded":
		ParseQueryInto(&v.ArgsPost, sc, string(body), lim)
	case "application/json":
		if err := ParseJSONInto(&v.ArgsJSON, sc, body, lim); err != nil {
			v.AddParseError("JSON 解析失败：" + err.Error())
		}
	case "application/xml", "text/xml":
		hasDTD, err := ParseXMLInto(&v.ArgsXML, sc, body, lim)
		if err != nil {
			v.AddParseError("XML 解析失败：" + err.Error())
		}
		if hasDTD {
			// 不在这里拦，只如实记录：拦截交给规则（XXE 类目记分）。
			v.AddParseError("XML 含 DOCTYPE/ENTITY 声明（XXE 载荷特征）")
		}
	case "multipart/form-data":
		if err := ParseMultipartInto(&v.ArgsPost, &v.Files, contentType, body, lim); err != nil {
			v.AddParseError("multipart 解析失败：" + err.Error())
		}
	default:
		// 未知类型：body 原文留在 v.Body，供 REQUEST_BODY 类规则使用。
		// 同时**不要静默**：如果声明了 Content-Type 但我们不认，记一条，
		// 免得攻击者用一个冷门类型把 payload 藏进"没人检查"的区域。
		if strings.Contains(contentType, "=") || contentType == "" {
			return
		}
		v.AddParseError("未支持的 Content-Type：" + mimeType)
	}
}

// ExpandNestedDocs 对每个参数值做"值级展开"。
//
// 这是为 crackweb 的"编码后的参数文档"手法准备的：
// 参数值本身是 JSON（可能再套一层 base64）时，payload 藏在文档字段里，
// 只比对整串值会漏掉。
//
// **展开结果必须同时写进 ARGS 合并视图**，这是一个真实绕过换来的教训：
// 原先只写 ArgsJSON，而 `MergeInto` 构造 ARGS 的动作发生在 ParseRequest 末尾、
// 即展开之前 —— 于是展开出来的字段进了一个**规则看不到的副本**，
// 等价于完全没展开。实测 `?id=<base64({"id":"1' UNION SELECT ..."})>`
// 明文同样的 payload 拦得住、编码后完全绕过（crackweb 报 Critical）。
//
// 必须显式调用（不在 ParseRequest 里默认做），因为它有 CPU 成本，
// 且只在存在相关规则时才值得付出。
func ExpandNestedDocs(v *tx.Collections, sc *Scratch, lim Limits) {
	// **所有参数来源都要展开**：原来源只取 GET/POST，
	// 于是 JSON body 里的 base64(JSON) 永远不展开 —— 而那正是
	// `internal/engine/nested_doc_test.go` 记录的那类真实绕过的兄弟形态。
	sources := []*tx.Params{&v.ArgsGet, &v.ArgsPost, &v.ArgsJSON, &v.ArgsXML}

	// 展开写入是**额外**增加参数，必须在源头就限住总量：
	// `MergeInto` 的 MaxParams*4 闸门在展开之前就跑完了，展开自己不受它约束，
	// 32 KiB 输入可以换出上万条 param 与几百 KB 的 arena 内存。
	budget := lim.MaxParams
	if budget <= 0 {
		budget = 1000
	}
	added := 0
	for _, src := range []*tx.Params{&v.ArgsGet, &v.ArgsPost, &v.ArgsJSON, &v.ArgsXML} {
		for i := 0; i < src.Len(); i++ {
			if added >= budget {
				v.AddParseError("值级文档展开达到数量上限：后续内层字段未被展开检查")
				return
			}
			added += expandOne(&v.Args, src.KeyAt(i), src.ValueAt(i), sc, lim)
		}
	}
	// ArgsJSON 另写一份，给显式声明 ARGS_JSON 的规则用（同样受总量约束）。
	for _, source := range sources {
		for i := 0; i < source.Len(); i++ {
			if added >= budget {
				return
			}
			added += expandOne(&v.ArgsJSON, source.KeyAt(i), source.ValueAt(i), sc, lim)
		}
	}
}

// expandOne 展开单个值，返回新增的参数条数。
func expandOne(dst *tx.Params, key, val []byte, sc *Scratch, lim Limits) int {
	if len(val) == 0 {
		return 0
	}
	before := dst.Len()
	// 值是 JSON 文档
	if val[0] == '{' || val[0] == '[' {
		prefix := append(append([]byte(nil), key...), '.')
		subScratch := &Scratch{Path: prefix}
		if err := ParseJSONInto(dst, subScratch, val, lim); err == nil {
			return dst.Len() - before
		}
	}
	// 值是 base64 包装的文档
	ParseBase64DocInto(dst, sc, string(key), val, lim, 1)
	return dst.Len() - before
}

func expandInto(dst *tx.Params, src *tx.Params, sc *Scratch, lim Limits, depth int) {
	for i := 0; i < src.Len(); i++ {
		key := src.KeyAt(i)
		val := src.ValueAt(i)
		if len(val) == 0 {
			continue
		}
		// 值是 JSON 文档
		if val[0] == '{' || val[0] == '[' {
			prefix := append(append([]byte(nil), key...), '.')
			subScratch := &Scratch{Path: prefix}
			if err := ParseJSONInto(dst, subScratch, val, lim); err == nil {
				continue
			}
		}
		// 值是 base64 包装的文档
		ParseBase64DocInto(dst, sc, string(key), val, lim, depth)
	}
}

// equalStringBytes 比较 string 与 []byte 的内容，**不分配**。
//
// `string(b) == s` 这种写法在某些场景下会被编译器优化掉，但传参/边界一变就不再成立；
// 这里显式逐字节比较，行为稳定且可读。
func equalStringBytes(s string, b []byte) bool {
	if len(s) != len(b) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != b[i] {
			return false
		}
	}
	return true
}

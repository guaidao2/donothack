// Package parser 把一次 HTTP 请求拆解成规则可以直接匹配的变量集合。
//
// 这一层是防绕过的核心（docs/DESIGN.md §8）：绕过 90% 发生在这里，而不是在规则里。
// 三条硬性要求：
//  1. **零分配热路径**：query 解析必须 0 allocs/op（有门禁测试钉住）。
//  2. **fail-open 但不静默**：任何异常都放行并记 ParseErrors，绝不 panic、绝不吞掉。
//  3. **逐项有界**：参数个数、值长度、URI 长度、JSON 深度/节点数全部有上限。
package parser

import "strings"

// NormalizePathInto 把原始请求路径规范化，结果写进 dst（复用）。
//
// 顺序固定，不可调换（docs/DESIGN.md §8.1）。攻击者专门利用
// "剥掉了 ../ 但把 // 折叠错"这类实现差异，所以顺序本身就是防线。
//
// 步骤：
//  0. 绝对形式（`http://host/path`）先剥掉 scheme 与 authority
//  1. 取 '?' 之前的部分
//  2. 去掉 '#' 之后的内容
//  3. 单次 %XX 解码（非法转义保留原样，**不因为解码失败就丢弃整个请求**）
//  4. 反斜杠归一为 '/'
//  5. 截断到 NUL 之前
//  6. 折叠连续 '/'
//  7. 消除 '.' 与 '..' 段
//  8. 再次折叠（'..' 消除可能又产生 '//'）
//  9. 长度上限
//
// 返回截断前的长度是否超过上限。
func NormalizePathInto(dst []byte, raw string, maxLen int) (out []byte, truncated bool) {
	dst = dst[:0]

	// 0) 绝对形式先剥 scheme/authority —— 放在最前面，
	//    否则 "http://h/a" 会被当成路径 "http:/h/a"。
	p := StripAbsoluteForm(raw)
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	// 2) 砍掉 fragment
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	// 3) 单次 URL 解码（写进 dst 的临时区）
	dst = appendPercentDecoded(dst, p, false)
	// 4) 反斜杠 → 斜杠；5) NUL 截断
	for i := 0; i < len(dst); i++ {
		switch dst[i] {
		case '\\':
			dst[i] = '/'
		case 0:
			dst = dst[:i]
			i = len(dst)
		}
	}
	// 6) 折叠连续 '/' 并去掉重复
	dst = collapseSlashes(dst)
	// 7) 消除 . 与 ..
	dst = removeDotSegments(dst)
	// 8) 再折叠一次
	dst = collapseSlashes(dst)
	// 9) 长度上限
	if maxLen > 0 && len(dst) > maxLen {
		dst = dst[:maxLen]
		truncated = true
	}
	return dst, truncated
}

// collapseSlashes 把连续 '/' 折成一个。
func collapseSlashes(b []byte) []byte {
	if len(b) < 2 {
		return b
	}
	w := 0
	prevSlash := false
	for _, c := range b {
		if c == '/' {
			if prevSlash {
				continue
			}
			prevSlash = true
		} else {
			prevSlash = false
		}
		b[w] = c
		w++
	}
	return b[:w]
}

// removeDotSegments 按 RFC 3986 消除 '.' 与 '..' 段。
//
// 实现为原地重写：逐段处理，遇到 ".." 回溯到上一段。
func removeDotSegments(b []byte) []byte {
	if len(b) == 0 {
		// 空路径视为根：直接返回一块写好的 "/"，避免调用方拿到空串。
		return append(b, '/')
	}
	// 输出缓冲区与输入共用一块内存是安全的：输出位置永远不超前于读取位置。
	out := b[:0]
	i := 0
	for i < len(b) {
		// 定位当前段
		start := i
		if b[i] == '/' {
			start = i + 1
		}
		end := start
		for end < len(b) && b[end] != '/' {
			end++
		}
		seg := b[start:end]

		switch {
		case isDotSegment(seg):
			// 丢弃；若后面还有段，保留一个斜杠
			i = end
			if i < len(b) {
				out = append(out, '/')
				i++
			}
		case isDotDotSegment(seg):
			// 回溯到上一个 '/' 之前
			for len(out) > 0 && out[len(out)-1] == '/' {
				out = out[:len(out)-1]
			}
			for len(out) > 0 && out[len(out)-1] != '/' {
				out = out[:len(out)-1]
			}
			i = end
			if i < len(b) {
				out = append(out, '/')
				i++
			}
		default:
			if start > 0 && (len(out) == 0 || out[len(out)-1] != '/') {
				out = append(out, '/')
			}
			out = append(out, seg...)
			i = end
		}
	}
	if len(out) == 0 {
		out = append(out, '/')
	}
	return out
}

// appendPercentDecoded 做 %XX 解码并把结果追加到 dst。
//
// 非法转义（如 "%ZZ"、结尾单个 '%'）**原样保留**：丢弃或报错都会给攻击者
// 制造"WAF 看到的路径与后端不同"的机会。
func appendPercentDecoded(dst []byte, s string, plusAsSpace bool) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s):
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				dst = append(dst, hi<<4|lo)
				i += 2
				continue
			}
			dst = append(dst, c)
		case c == '%' && i+2 == len(s):
			// "%X" 这种截断的转义：原样保留
			dst = append(dst, c)
		case plusAsSpace && c == '+':
			dst = append(dst, ' ')
		default:
			dst = append(dst, c)
		}
	}
	return dst
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// isDotSegment / isDotDotSegment 用手写比较，避免 string(seg) 带来的分配。
func isDotSegment(seg []byte) bool {
	return len(seg) == 1 && seg[0] == '.'
}

func isDotDotSegment(seg []byte) bool {
	return len(seg) == 2 && seg[0] == '.' && seg[1] == '.'
}

// StripAbsoluteForm 处理绝对形式的 request-target。
//
// HTTP/1.1 允许代理发 `GET http://host/path?q=1 HTTP/1.1`（absolute-form）。
// 如果解析层只当它是普通路径，规范化结果会变成 "http:/host/path"，
// 规则匹配的就是一个后端根本不会执行的路径 —— 这既是漏检也是误报来源。
func StripAbsoluteForm(uri string) string {
	if len(uri) < 7 {
		return uri
	}
	var prefix string
	switch {
	case hasPrefixFold(uri, "http://"):
		prefix = "http://"
	case hasPrefixFold(uri, "https://"):
		prefix = "https://"
	default:
		return uri
	}
	rest := uri[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[i:]
	}
	// 没有路径部分：可能只有 query，也可能是裸 authority
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		return "/" + rest[i:]
	}
	return "/"
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

// SplitURI 把 request-target 拆成路径部分与 query 部分（都不含分隔符）。
func SplitURI(uri string) (path, query string) {
	u := StripAbsoluteForm(uri)
	if i := strings.IndexByte(u, '?'); i >= 0 {
		return u[:i], u[i+1:]
	}
	return u, ""
}

// IsTextContentType 判断 Content-Type 是否值得做请求体解析。
func IsTextContentType(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/x-www-form-urlencoded",
		"application/json",
		"application/xml",
		"text/xml",
		"text/plain",
		"multipart/form-data":
		return true
	}
	// 形如 application/vnd.api+json
	return strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")
}

// SplitContentType 拆出 mime 与 charset。
func SplitContentType(ct string) (mime, charset string) {
	parts := strings.Split(ct, ";")
	mime = strings.ToLower(strings.TrimSpace(parts[0]))
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if len(p) > 8 && strings.EqualFold(p[:8], "charset=") {
			charset = strings.TrimSpace(p[8:])
		}
	}
	return mime, charset
}

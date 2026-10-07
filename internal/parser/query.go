package parser

import (
	"donothack/internal/tx"
)

// Scratch 是解析期的可复用临时缓冲。
//
// 存在的意义就是**不分配**：解码后的键值先写在这里，再被拷进 Params 的 arena。
// 每个请求复用一个 Scratch，稳态下零分配。
type Scratch struct {
	Key []byte
	Val []byte
	// Aux 用于值级递归展开（JSON / base64 文档）时的中间结果。
	Aux []byte
	// Body 是原始请求体的缓冲（要原样转发给上游，所以单独放）。
	Body []byte
	// Inspect 是真正参与检测的字节（可能是解压后的）。
	Inspect []byte
	// Path 是 JSON / XML 展开时的路径栈。
	Path []byte
	// Num 是数字转文本的临时区。
	Num []byte
}

// Reset 清空但保留容量。
func (s *Scratch) Reset() {
	s.Key = s.Key[:0]
	s.Val = s.Val[:0]
	s.Aux = s.Aux[:0]
	s.Body = s.Body[:0]
	s.Inspect = s.Inspect[:0]
	s.Path = s.Path[:0]
	s.Num = s.Num[:0]
}

// Limits 是解析层的各项上限。全部必须有界。
type Limits struct {
	MaxParams       int // 单个集合的参数个数上限
	MaxParamValLen  int // 单个参数值的字节上限
	MaxURILength    int
	MaxHeaders      int
	MaxInspectBody  int // 请求体检查上限（字节）
	MaxJSONDepth    int
	MaxJSONNodes    int
	MaxNestedDecode int // 值级递归展开的层数上限
}

// DefaultLimits 返回与 medium 档一致的默认值。
func DefaultLimits() Limits {
	return Limits{
		MaxParams:       1000,
		MaxParamValLen:  64 << 10,
		MaxURILength:    8192,
		MaxHeaders:      100,
		MaxInspectBody:  512 << 10,
		MaxJSONDepth:    32,
		MaxJSONNodes:    10000,
		MaxNestedDecode: 3,
	}
}

// ParseQueryInto 解析 query string 或 form-urlencoded body，写入 dst。
//
// **这是热路径上唯一被门禁钉住必须 0 allocs/op 的函数**（见 params_bench_test.go）。
// 因此：
//   - 不用 net/url（每参数多次分配），手写扫描
//   - 不用 strings.Split（每次分配切片头）
//   - 不把 []byte 转 string
//
// 分隔符同时接受 '&' 与 ';'：不同后端对 ';' 的处理不一致，
// 我们**多切一刀**是安全方向（宁可多看见一个参数，也不要少看）。
//
// 同名参数全部保留（HPP）。
func ParseQueryInto(dst *tx.Params, sc *Scratch, raw string, lim Limits) {
	i := 0
	n := len(raw)
	for i <= n {
		// 定位一个 pair
		start := i
		for i < n && raw[i] != '&' && raw[i] != ';' {
			i++
		}
		pair := raw[start:i]
		if len(pair) > 0 {
			sc.Key = sc.Key[:0]
			sc.Val = sc.Val[:0]
			if eq := indexByte(pair, '='); eq >= 0 {
				sc.Key = appendPercentDecoded(sc.Key, pair[:eq], true)
				sc.Val = appendPercentDecoded(sc.Val, pair[eq+1:], true)
			} else {
				sc.Key = appendPercentDecoded(sc.Key, pair, true)
				// 片段里带空格、斜杠、`$` 这类**不可能是参数名**的字符时，
				// 它更可能是被我们"多切一刀"（`;` 也当分隔符）切出来的**值** ——
				// 后端只按 '&' 切（PHP 默认如此），会把 `cat /etc/passwd` 整段
				// 留在前一个参数的值里，这份证据不能丢（实测：同一载荷放 body 被拦、
				// 放 query 直接执行）。所以再当值收一份。
				//
				// 纯标识符片段（`?debug` 这种 flag）保持"值 = 空串"的 PHP 语义不变，
				// 免得把每个 flag 都变成两个参数、顺带抬高 ARGS_COUNT。
				if !isPlainParamName(pair) {
					sc.Val = appendPercentDecoded(sc.Val, pair, true)
				}
			}
			if len(sc.Val) > lim.MaxParamValLen {
				sc.Val = sc.Val[:lim.MaxParamValLen]
				dst.MarkTooLong()
			}
			if dst.Len() >= lim.MaxParams {
				dst.MarkTruncated()
				return
			}
			dst.Add(sc.Key, sc.Val)
		}
		i++ // 跳过分隔符
	}
}

// isPlainParamName 判断片段是不是"普通参数名"（只含字母数字、下划线、连字符）。
// 用来区分 `?debug` 这种正常 flag 与 `cat /etc/passwd` 这种被误切出来的值。
func isPlainParamName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

// indexByte 是 strings.IndexByte 的本地版本（避免引入 strings 的调用开销，语义相同）。
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// ParseHeadersInto 把请求头装进集合。键统一小写（规则侧只写小写）。
func ParseHeadersInto(dst *tx.Params, src map[string][]string, sc *Scratch, lim Limits) {
	n := 0
	for k, vs := range src {
		if n >= lim.MaxHeaders {
			dst.MarkTruncated()
			return
		}
		sc.Key = sc.Key[:0]
		sc.Key = appendLowerASCII(sc.Key, k)
		for _, v := range vs {
			sc.Val = sc.Val[:0]
			sc.Val = append(sc.Val, v...)
			if len(sc.Val) > lim.MaxParamValLen {
				sc.Val = sc.Val[:lim.MaxParamValLen]
				dst.MarkTooLong()
			}
			dst.Add(sc.Key, sc.Val)
			n++
			if n >= lim.MaxHeaders {
				dst.MarkTruncated()
				return
			}
		}
	}
}

// appendLowerASCII 追加 ASCII 小写形式（不分配，不走 Unicode 慢路径）。
func appendLowerASCII(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

// ParseCookiesInto 解析 Cookie 头。同名 cookie 同样全部保留。
func ParseCookiesInto(dst *tx.Params, cookieHeader string, sc *Scratch, lim Limits) {
	i := 0
	n := len(cookieHeader)
	for i < n {
		for i < n && (cookieHeader[i] == ' ' || cookieHeader[i] == ';' || cookieHeader[i] == ',') {
			i++
		}
		start := i
		for i < n && cookieHeader[i] != ';' && cookieHeader[i] != ',' {
			i++
		}
		pair := cookieHeader[start:i]
		if len(pair) > 0 {
			sc.Key = sc.Key[:0]
			sc.Val = sc.Val[:0]
			if eq := indexByte(pair, '='); eq >= 0 {
				sc.Key = appendPercentDecoded(sc.Key, trimSpace(pair[:eq]), false)
				sc.Val = appendPercentDecoded(sc.Val, trimSpace(pair[eq+1:]), false)
			} else {
				sc.Key = appendPercentDecoded(sc.Key, trimSpace(pair), false)
			}
			if len(sc.Val) > lim.MaxParamValLen {
				sc.Val = sc.Val[:lim.MaxParamValLen]
				dst.MarkTooLong()
			}
			if dst.Len() >= lim.MaxParams {
				dst.MarkTruncated()
				return
			}
			dst.Add(sc.Key, sc.Val)
		}
	}
}

func trimSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	j := len(s)
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

// MergeInto 把 src 的全部参数追加进 dst（用于构造 ARGS 合并视图）。
func MergeInto(dst, src *tx.Params, lim Limits) {
	for i := 0; i < src.Len(); i++ {
		if dst.Len() >= lim.MaxParams*4 {
			dst.MarkTruncated()
			return
		}
		dst.Add(src.KeyAt(i), src.ValueAt(i))
	}
}

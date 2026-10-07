// Package transform 实现规则里的变换链。
//
// 变换是防编码绕过的核心：crackweb 这类扫描器不自带 payload 而是**推导**它们 ——
// 结构改写（注释分割、关键字拆分、空白替换）叠编码（URL、双 URL、Unicode、hex、
// HTML 实体、base64）按代数升级。所以规则不能直接拿原始值去比，
// 必须先"洗"成规范形态。
//
// 三条约束：
//  1. 变换**不得原地修改入参**（入参可能是共享的 body 切片）。
//  2. 变换失败（如非法 base64）**返回原值**并让调用方计数，不中断规则评估。
//  3. 每个变换都有迭代/输出上限，防止嵌套编码把 CPU 拖死。
package transform

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"donothack/internal/kv"
)

// Func 是变换函数的签名。
//
// dst 是调用方给的输出缓冲：容量够就直接往里写（**零分配**），不够就自己 make。
// 这条约定是热路径零分配的关键 —— 变换链在正常请求上要跑「链数 × 值数」次，
// 每次都 make 一块缓冲的话，光这一处就是每请求几十次分配。
//
// 两条必须守住的不变量：
//  1. **不得原地修改 in**（in 可能是共享的 body 切片，也可能是 arena 里前一步的输出）；
//  2. **返回 in 本身是合法的**（表示"这一步没改动"），调用方按需处理。
type Func func(dst, in []byte, params kv.Params) ([]byte, error)

// grow 取一块长度为 n 的输出缓冲：调用方给的 dst 容量够就用它（零分配）。
//
// 与 `append(dst[:0], ...)` 的分工：变长输出用 append 形态，定长输出（编解码）用 grow。
func grow(dst []byte, n int) []byte {
	if cap(dst) >= n {
		return dst[:n]
	}
	return make([]byte, n)
}

var registry = map[string]Func{}

// Register 注册一个变换。重名会 panic —— 这是编译期错误，必须在启动时炸出来。
func Register(name string, fn Func) {
	if _, dup := registry[name]; dup {
		panic("transform: 重复注册 " + name)
	}
	registry[name] = fn
}

// Lookup 查找变换。
func Lookup(name string) (Func, bool) {
	fn, ok := registry[name]
	return fn, ok
}

// Exists 判断变换是否已注册。
func Exists(name string) bool {
	_, ok := registry[name]
	return ok
}

// Names 返回全部已注册的变换名（排序）。
func Names() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Suggestion 在名字写错时给出最接近的候选。
func Suggestion(name string) string {
	best, bestDist := "", 1<<30
	for _, n := range Names() {
		d := editDistance(strings.ToLower(name), strings.ToLower(n))
		if d < bestDist {
			best, bestDist = n, d
		}
	}
	if bestDist <= 3 {
		return best
	}
	return ""
}

func editDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

// ---------------------------------------------------------------- 基础

func init() {
	Register("none", func(dst, in []byte, _ kv.Params) ([]byte, error) { return in, nil })

	Register("lowercase", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasUpperASCII(in) {
			return in, nil
		}
		// 先整段拷进 dst，再在原地改大小写。
		// dst 是调用方给的**输出**缓冲，改它不违反"不得修改入参"——
		// 这一点很关键：in 可能是共享的 body 切片，也可能是 arena 里前一步的输出。
		out := append(dst[:0], in...)
		for i, c := range out {
			if c >= 'A' && c <= 'Z' {
				out[i] = c + 'a' - 'A'
			}
		}
		return out, nil
	})

	Register("uppercase", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasLowerASCII(in) {
			return in, nil
		}
		out := append(dst[:0], in...)
		for i, c := range out {
			if c >= 'a' && c <= 'z' {
				out[i] = c - ('a' - 'A')
			}
		}
		return out, nil
	})

	Register("trim", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if isTrimmed(in) {
			return in, nil
		}
		return bytes.TrimSpace(in), nil
	})
}

// ---------------------------------------------------------------- 编码解码

// urlDecodeOnce 做一次 %XX 解码。非法转义原样保留。
func urlDecodeOnce(dst, in []byte) []byte {
	out := dst[:0]
	for i := 0; i < len(in); i++ {
		if in[i] == '%' && i+2 < len(in) {
			hi, ok1 := unhex(in[i+1])
			lo, ok2 := unhex(in[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, in[i])
	}
	return out
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

func init() {
	Register("urlDecode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '%') {
			return in, nil
		}
		return urlDecodeOnce(dst, in), nil
	})

	// 连续解码两次：对抗 %2527 这种"双写"绕过。
	Register("doubleUrlDecode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '%') {
			return in, nil
		}
		// 第一次解到 dst；第二次起点另取一块（这里让 append 自己扩容即可，
		// 因为入口是独立的 in 切片，r 与 dst 不重叠时才能这么写）。
		r := urlDecodeOnce(dst, in)
		return urlDecodeOnce(nil, r), nil
	})

	// %u0041 形式（IIS/老式 unicode 编码）
	Register("urlDecodeUni", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '%') {
			return in, nil
		}
		out := dst[:0]
		for i := 0; i < len(in); i++ {
			if in[i] == '%' && i+5 < len(in) && (in[i+1] == 'u' || in[i+1] == 'U') {
				v := 0
				ok := true
				for k := 0; k < 4; k++ {
					h, good := unhex(in[i+2+k])
					if !good {
						ok = false
						break
					}
					v = v<<4 | int(h)
				}
				if ok {
					var buf [4]byte
					n := utf8.EncodeRune(buf[:], rune(v))
					out = append(out, buf[:n]...)
					i += 5
					continue
				}
			}
			out = append(out, in[i])
		}
		return out, nil
	})

	Register("base64Decode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !looksBase64ish(in) {
			return in, nil
		}
		buf := grow(dst, base64.StdEncoding.DecodedLen(len(in)))
		n, err := base64.StdEncoding.Decode(buf, in)
		if err != nil {
			// 解码失败返回原值：变换失败不该中断规则评估。
			return in, nil
		}
		return buf[:n], nil
	})

	Register("base64DecodeExt", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !looksBase64ish(in) {
			return in, nil
		}
		s := strings.TrimRight(string(in), "=")
		for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
			buf := grow(dst, enc.DecodedLen(len(s)))
			n, err := enc.Decode(buf, []byte(s))
			if err == nil {
				return buf[:n], nil
			}
		}
		return in, nil
	})

	Register("hexDecode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !isHexString(bytes.TrimSpace(in)) {
			return in, nil
		}
		buf := grow(dst, hex.DecodedLen(len(in)))
		n, err := hex.Decode(buf, bytes.TrimSpace(in))
		if err != nil {
			return in, nil
		}
		return buf[:n], nil
	})

	Register("hexEncode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		buf := grow(dst, hex.EncodedLen(len(in)))
		hex.Encode(buf, in)
		return buf, nil
	})

	// 0x4142 或 X'4142' 形式的 SQL hex 字面量
	Register("sqlHexDecode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		s := bytes.TrimSpace(in)
		if len(s) > 2 && (s[0] == '0') && (s[1] == 'x' || s[1] == 'X') {
			s = s[2:]
		} else if len(s) > 3 && (s[0] == 'X' || s[0] == 'x') && s[1] == '\'' && s[len(s)-1] == '\'' {
			s = s[2 : len(s)-1]
		} else {
			return in, nil
		}
		buf := grow(dst, hex.DecodedLen(len(s)))
		n, err := hex.Decode(buf, s)
		if err != nil {
			return in, nil
		}
		return buf[:n], nil
	})

	Register("htmlEntityDecode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '&') {
			return in, nil
		}
		return htmlEntityDecode(dst, in), nil
	})

	Register("jsDecode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '\\') {
			return in, nil
		}
		return jsDecode(dst, in), nil
	})

	Register("cssDecode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '\\') {
			return in, nil
		}
		return cssDecode(dst, in), nil
	})

	Register("escapeSeqDecode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '\\') {
			return in, nil
		}
		out := dst[:0]
		for i := 0; i < len(in); i++ {
			if in[i] == '\\' && i+1 < len(in) {
				switch in[i+1] {
				case 'n':
					out = append(out, '\n')
				case 'r':
					out = append(out, '\r')
				case 't':
					out = append(out, '\t')
				case '0':
					out = append(out, 0)
				case '\\':
					out = append(out, '\\')
				case '\'', '"':
					out = append(out, in[i+1])
				default:
					out = append(out, in[i])
					continue
				}
				i++
				continue
			}
			out = append(out, in[i])
		}
		return out, nil
	})
}

var htmlEntities = map[string]byte{
	"lt": '<', "gt": '>', "amp": '&', "quot": '"', "apos": '\'',
	"nbsp": ' ', "colon": ':', "sol": '/', "lpar": '(', "rpar": ')',
	"num": '#', "percnt": '%', "plus": '+', "comma": ',', "period": '.',
	"equals": '=', "quest": '?', "semi": ';', "commat": '@',
}

func htmlEntityDecode(dst, in []byte) []byte {
	out := dst[:0]
	for i := 0; i < len(in); i++ {
		if in[i] != '&' {
			out = append(out, in[i])
			continue
		}
		end := bytes.IndexByte(in[i:], ';')
		if end < 0 || end > 12 {
			out = append(out, in[i])
			continue
		}
		ent := in[i+1 : i+end]
		switch {
		case len(ent) > 1 && ent[0] == '#':
			var v int
			var err error
			if len(ent) > 2 && (ent[1] == 'x' || ent[1] == 'X') {
				v64, e := strconv.ParseInt(string(ent[2:]), 16, 32)
				v, err = int(v64), e
			} else {
				v, err = strconv.Atoi(string(ent[1:]))
			}
			if err == nil && v > 0 && v < utf8.RuneSelf {
				out = append(out, byte(v))
				i += end
				continue
			}
			if err == nil && v >= utf8.RuneSelf {
				var buf [4]byte
				n := utf8.EncodeRune(buf[:], rune(v))
				out = append(out, buf[:n]...)
				i += end
				continue
			}
		default:
			if b, ok := htmlEntities[strings.ToLower(string(ent))]; ok {
				out = append(out, b)
				i += end
				continue
			}
		}
		out = append(out, in[i])
	}
	return out
}

func jsDecode(dst, in []byte) []byte {
	out := dst[:0]
	for i := 0; i < len(in); i++ {
		if in[i] != '\\' || i+1 >= len(in) {
			out = append(out, in[i])
			continue
		}
		switch in[i+1] {
		case 'u':
			// \uXXXX 或 \u{XXXX}
			if i+2 < len(in) && in[i+2] == '{' {
				if end := bytes.IndexByte(in[i+3:], '}'); end > 0 && end <= 6 {
					if v, err := strconv.ParseInt(string(in[i+3:i+3+end]), 16, 32); err == nil {
						var buf [4]byte
						n := utf8.EncodeRune(buf[:], rune(v))
						out = append(out, buf[:n]...)
						i += 3 + end
						continue
					}
				}
			} else if i+5 < len(in) {
				if v, err := strconv.ParseInt(string(in[i+2:i+6]), 16, 32); err == nil {
					var buf [4]byte
					n := utf8.EncodeRune(buf[:], rune(v))
					out = append(out, buf[:n]...)
					i += 5
					continue
				}
			}
		case 'x':
			if i+3 < len(in) {
				if v, err := strconv.ParseInt(string(in[i+2:i+4]), 16, 32); err == nil {
					out = append(out, byte(v))
					i += 3
					continue
				}
			}
		}
		out = append(out, in[i])
	}
	return out
}

func cssDecode(dst, in []byte) []byte {
	out := dst[:0]
	for i := 0; i < len(in); i++ {
		if in[i] != '\\' || i+1 >= len(in) {
			out = append(out, in[i])
			continue
		}
		j := i + 1
		v := 0
		digits := 0
		for j < len(in) && digits < 6 {
			h, ok := unhex(in[j])
			if !ok {
				break
			}
			v = v<<4 | int(h)
			j++
			digits++
		}
		if digits == 0 {
			out = append(out, in[i])
			continue
		}
		// CSS 允许一个空白作为转义结束符
		if j < len(in) && (in[j] == ' ' || in[j] == '\t') {
			j++
		}
		var buf [4]byte
		n := utf8.EncodeRune(buf[:], rune(v))
		out = append(out, buf[:n]...)
		i = j - 1
	}
	return out
}

// ---------------------------------------------------------------- 清洗

func init() {
	// 去注释：/* */、--、#、<!-- -->
	//
	// crackweb 的"结构改写"里第一条就是注释分割（UN/**/ION），
	// 所以这条变换是必挂的。
	Register("removeComments", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasCommentMarker(in) {
			return in, nil
		}
		return replaceComments(dst, in, nil), nil
	})

	Register("replaceComments", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasCommentMarker(in) {
			return in, nil
		}
		return replaceComments(dst, in, []byte{' '}), nil
	})

	Register("removeNulls", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, 0) {
			return in, nil
		}
		return bytes.ReplaceAll(in, []byte{0}, nil), nil
	})

	// normalizeIFS 把 shell 里"当空格用"的写法折叠成真空格。
	//
	// 为什么需要：`;cat${IFS}/etc/passwd` 里的 `${IFS}` 语义上就是一个空格，
	// 但下游规则的 `\s+` 与"分隔符 + 命令名"判定都认不出来 —— 实测这样能整条绕过
	// 命令注入检测（cracker 的 `; cat${IFS}/etc/pass?d` 就是这么过去的）。
	// 折叠之后原有规则一字不改就能命中，不必为每个惯用法再加一条规则。
	//
	// 只处理这个惯用法：`${IFS}`、`$IFS`（大小写）、`${IFS%…}` / `${IFS:…}` 这类带修饰的，
	// 以及紧随其后的 `$9`（`$IFS$9` 也是常见写法）。
	//
	// **不要把它挂到"检测 ${IFS} 本身"的规则上** —— 那会把证据折掉，
	// 与 compressWhitespace 把 `\n` 折成空格那次是同一类错误。
	// removeShellQuotes 删掉引号字符（0x27 单引号、0x22 双引号）。
	//
	// shell 里引号是"拼接分隔符"，会被解释器消掉：`c''ertutil -urlcache` 与
	// `certutil -urlcache`、`c'a't` 与 `cat` 执行的是同一个命令 ——
	// 这是绕关键字黑名单的老手法，而带引号的形态配不上任何字面量
	// （实测 `c''ertutil -urlcache …` 曾整条漏检）。
	//
	// 只挂到**模式里不含引号**的 shell 规则上（6004/6005/6006/6013/6014）；
	// 6003 的正则本身就带引号转义，挂上去会自毁。
	// expandShellVars 处理 shell 的变量装配与替换。
	//
	// 为什么必须有：`a=id;$a` 执行的是 `id`，但字面 "id" 只出现在赋值里、
	// 真正执行的位置是 `$a` —— 只看字面 token 的检测会整条穿过。
	// 这里做两件事（都在同一遍里，输出写进调用方的 dst）：
	//   1) 把简单的 `name=value` 赋值记下来，遇到 `$name` 用它替换 → 还原出真正的命令名；
	//   2) shell 里会展开成空的东西直接去掉：`$@`、`$*`、`${...}`、未赋值的 `$name`
	//      （`i$@d` 在 shell 里就是 `id`）。
	// 没有 `$` 时立刻返回入参，热路径不留额外开销。
	Register("expandShellVars", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '$') {
			return in, nil
		}
		type assign struct{ name, val []byte }
		var assigns [4]assign
		nAssign := 0
		// 收集赋值（值不含空白与 shell 分隔符，片段长度有上限）
		for i := 0; i < len(in) && nAssign < len(assigns); i++ {
			if !isNameStart(in[i]) {
				continue
			}
			k := i
			for k < len(in) && isNameChar(in[k]) {
				k++
			}
			if k >= len(in) || in[k] != '=' || k-i > 32 {
				continue
			}
			v := k + 1
			e := v
			for e < len(in) && !isShellDelim(in[e]) {
				e++
			}
			if e-v > 256 {
				continue
			}
			assigns[nAssign] = assign{name: in[i:k], val: in[v:e]}
			nAssign++
			i = e - 1
		}
		out := dst[:0]
		changed := false
		for i := 0; i < len(in); {
			if in[i] != '$' {
				out = append(out, in[i])
				i++
				continue
			}
			changed = true
			j := i + 1
			braced := false
			if j < len(in) && in[j] == '{' {
				braced = true
				j++
			}
			// `$@` / `$*`：shell 里展开成位置参数，通常为空
			if !braced && j < len(in) && (in[j] == '@' || in[j] == '*') {
				i = j + 1
				continue
			}
			s := j
			for j < len(in) && isNameChar(in[j]) {
				j++
			}
			name := in[s:j]
			if braced {
				if j < len(in) && in[j] == '}' {
					j++
				} else {
					out = append(out, in[i])
					i++
					continue
				}
			}
			if len(name) == 0 {
				out = append(out, in[i]) // 单独的 `$`，原样保留
				i++
				continue
			}
			replaced := false
			for k := 0; k < nAssign; k++ {
				if bytes.Equal(assigns[k].name, name) {
					out = append(out, assigns[k].val...)
					replaced = true
					break
				}
			}
			if !replaced {
				// 未赋值：shell 展开成空，这里也去掉（`i$@d` 这类拼装的要害）
			}
			i = j
		}
		if !changed {
			return in, nil
		}
		return out, nil
	})

	// removeShellEscapes 去掉反斜杠转义：shell 会把 `\x` 解释成 `x`，
	// 于是 `i\d` 执行的是 `id`、`c\at` 执行的是 `cat`。
	// 检测侧如果只在原样字符串上匹配命令名，这类写法整条穿过。
	Register("removeShellEscapes", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '\\') {
			return in, nil
		}
		out := dst[:0]
		for i := 0; i < len(in); i++ {
			if in[i] == '\\' && i+1 < len(in) {
				continue // 跳过反斜杠，保留被转义的字符
			}
			out = append(out, in[i])
		}
		return out, nil
	})

	Register("removeShellQuotes", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, 39) && !hasByte(in, 34) {
			return in, nil
		}
		out := dst[:0]
		for i := 0; i < len(in); i++ {
			if in[i] == 39 || in[i] == 34 {
				continue
			}
			out = append(out, in[i])
		}
		return out, nil
	})

	Register("normalizeIFS", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !hasByte(in, '$') {
			return in, nil
		}
		out := dst[:0]
		for i := 0; i < len(in); {
			if in[i] == '$' {
				// ${IFS} / ${ifs} / ${IFS%??} / ${IFS:0:1}
				if i+1 < len(in) && in[i+1] == '{' {
					if end := bytes.IndexByte(in[i+2:], '}'); end >= 0 {
						if isIFSWord(in[i+2 : i+2+end]) {
							out = append(out, ' ')
							i += 2 + end + 1
							continue
						}
					}
				}
				// $IFS / $ifs
				if i+4 <= len(in) && equalFoldASCII(in[i+1:i+4], "ifs") {
					out = append(out, ' ')
					i += 4
					// `$IFS$9` 里那个 $9
					if i+2 <= len(in) && in[i] == '$' && in[i+1] == '9' {
						i += 2
					}
					continue
				}
			}
			out = append(out, in[i])
			i++
		}
		return out, nil
	})

	Register("compressWhitespace", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !needsCompressWhitespace(in) {
			return in, nil
		}
		out := dst[:0]
		prevWS := false
		for _, c := range in {
			isWS := c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
			if isWS {
				if prevWS {
					continue
				}
				out = append(out, ' ')
				prevWS = true
				continue
			}
			out = append(out, c)
			prevWS = false
		}
		return out, nil
	})

	Register("removeWhitespace", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		if !anyByte(in, " \t\n\r\v\f") {
			return in, nil
		}
		out := dst[:0]
		for _, c := range in {
			switch c {
			case ' ', '\t', '\n', '\r', '\v', '\f':
				continue
			}
			out = append(out, c)
		}
		return out, nil
	})

	Register("length", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		return strconv.AppendInt(nil, int64(len(in)), 10), nil
	})

	Register("sha1", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		sum := sha1.Sum(in)
		return []byte(hex.EncodeToString(sum[:])), nil
	})

	Register("md5", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		sum := md5.Sum(in)
		return []byte(hex.EncodeToString(sum[:])), nil
	})

	// 命令行长参数归并：把 "a  b"、"a\tb" 折成单空格，去掉引号噪声。
	Register("cmdLine", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		// 中间两步 bytes.ReplaceAll 自己会分配（它们返回新切片），
		// 所以这里只保证入口与出口走 dst。
		out, _ := registry["compressWhitespace"](dst, in, nil)
		out = bytes.ReplaceAll(out, []byte(`"`), []byte(` `))
		out = bytes.ReplaceAll(out, []byte(`'`), []byte(` `))
		return registry["compressWhitespace"](nil, out, nil)
	})

	// utf8 → \uXXXX 形式（把多字节字符统一成转义，便于比对）
	Register("utf8ToUnicode", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		var sb strings.Builder
		for _, r := range string(in) {
			if r < utf8.RuneSelf {
				sb.WriteByte(byte(r))
				continue
			}
			fmt.Fprintf(&sb, "\\u%04x", r)
		}
		return []byte(sb.String()), nil
	})

	// 路径规范化（与 parser 里的实现保持一致的语义；这里独立实现，
	// 因为 transform 与 parser 在依赖图上是兄弟，互不依赖）
	Register("normalizePath", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		return normalizePath(dst, in, false), nil
	})
	Register("normalizePathWin", func(dst, in []byte, _ kv.Params) ([]byte, error) {
		return normalizePath(dst, in, true), nil
	})
}

// mysqlExecCommentBody 判断这段注释体是不是 MySQL/MariaDB 的"可执行注释"，
// 是就返回"要去掉版本号之后的内容"，不是返回 nil。
//
// 形态：`!50000UNION`、`!UNION`、`M!50000UNION`（MariaDB）。
func mysqlExecCommentBody(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	b := body
	switch {
	case b[0] == '!':
		b = b[1:]
	case len(b) > 1 && (b[0] == 'M' || b[0] == 'm') && b[1] == '!':
		b = b[2:]
	default:
		return nil
	}
	// 开头的 5~6 位版本号（`/*!50000UNION*/`）不是语句的一部分
	k := 0
	for k < len(b) && k < 6 && b[k] >= '0' && b[k] <= '9' {
		k++
	}
	return b[k:]
}

// isIFSWord 判断 `${...}` 里的内容是不是"当空格用"的 IFS：
// `IFS`、`ifs`，以及带修饰的 `IFS%??` / `IFS:0:1`（取前几位之类）。
// 只认开头是 ifs 且后面跟修饰符的形态，避免把 `${ifs_thing}` 这种正常变量名折掉。
func isIFSWord(b []byte) bool {
	if len(b) < 3 || !equalFoldASCII(b[:3], "ifs") {
		return false
	}
	if len(b) == 3 {
		return true
	}
	switch b[3] {
	case '%', ':', '#', '/':
		return true
	}
	return false
}

// equalFoldASCII 是忽略大小写的三字节比较（变换跑在热路径上，不值得为它引 strings）。
func equalFoldASCII(b []byte, want string) bool {
	if len(b) != len(want) {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		w := want[i]
		if w >= 'A' && w <= 'Z' {
			w += 'a' - 'A'
		}
		if c != w {
			return false
		}
	}
	return true
}

// replaceComments 去掉 /* */、-- 行注释、#、<!-- -->。
// if with != nil 时用 with 替换成一个空格（避免把"UN/**/ION"变成"UNION"之外还粘连别的）。
//
// **例外：MySQL / MariaDB 的"可执行注释" `/*!…*/` 与 `/*M!…*/` 要保留内容**。
// 这类注释里的语句数据库会真的执行（`/*!50000UNION*/ SELECT` 等价于 `UNION SELECT`），
// 所以把它当普通注释整段删掉，等于帮攻击者把证据擦掉 —— 实测
// `?id=1 /*!50000UNION*/ SELECT 1,2,3` 曾整条漏检。
// 处理方式：去掉边界与开头的版本号数字，保留里面的语句。
func replaceComments(dst, in []byte, with []byte) []byte {
	out := dst[:0]
	for i := 0; i < len(in); {
		switch {
		case i+1 < len(in) && in[i] == '/' && in[i+1] == '*':
			end := bytes.Index(in[i+2:], []byte("*/"))
			if end < 0 {
				i = len(in)
				continue
			}
			body := in[i+2 : i+2+end]
			if exec := mysqlExecCommentBody(body); exec != nil {
				out = append(out, ' ')
				out = append(out, exec...)
				out = append(out, ' ')
			} else if with != nil {
				out = append(out, with...)
			}
			i += 2 + end + 2
		case i+3 < len(in) && in[i] == '<' && in[i+1] == '!' && in[i+2] == '-' && in[i+3] == '-':
			end := bytes.Index(in[i+4:], []byte("-->"))
			if end < 0 {
				i = len(in)
				continue
			}
			if with != nil {
				out = append(out, with...)
			}
			i += 4 + end + 3
		case i+1 < len(in) && in[i] == '-' && in[i+1] == '-':
			// '--' 是行注释：连同行尾换行一起去掉（换行是它的终止符）
			end := bytes.IndexByte(in[i:], '\n')
			if end < 0 {
				i = len(in)
				continue
			}
			if with != nil {
				out = append(out, with...)
			}
			i += end + 1
		default:
			out = append(out, in[i])
			i++
		}
	}
	return out
}

func normalizePath(dst, in []byte, win bool) []byte {
	b := dst[:0]
	b = append(b, urlDecodeOnce(dst, in)...)
	for i := range b {
		if b[i] == '\\' && win {
			b[i] = '/'
		}
		if b[i] == 0 {
			b = b[:i]
			break
		}
	}
	// 折叠 //
	out := dst[:0]
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
		out = append(out, c)
	}
	// 消除 ./..
	segs := bytes.Split(out, []byte{'/'})
	stack := make([][]byte, 0, len(segs))
	for _, s := range segs {
		switch string(s) {
		case ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, s)
		}
	}
	res := bytes.Join(stack, []byte{'/'})
	if len(res) == 0 || res[0] != '/' {
		res = append([]byte{'/'}, res...)
	}
	return res
}

// isNameStart / isNameChar 判定 shell 变量名（只认 ASCII 字母与下划线开头）。
func isNameStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isNameChar(c byte) bool {
	return isNameStart(c) || (c >= '0' && c <= '9')
}

// isShellDelim 是赋值取值时的边界：空白与 shell 分隔符。
func isShellDelim(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', ';', '&', '|', '+':
		return true
	}
	return false
}

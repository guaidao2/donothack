package transform

import (
	"strings"
)

// 本文件提供"**结果与输入相同就返回输入**"的快速判定。
//
// 为什么值得单独一层：变换链是热路径上最大的分配来源 ——
// 每个变换都会 `make` 一块新缓冲，而**正常业务参数绝大多数不需要任何变换**
// （已经是小写、没有 % 转义、没有空白折叠）。实测 4 条规则的基准里，
// 每个请求要跑「链数 × 值数」次变换，一下子就 90+ 次分配。
//
// 这里的判定只做一次线性扫描（比分配 + 拷贝便宜得多），命中就直接返回入参切片。
// 变换实现**必须**遵守"不得原地修改入参"这条约束，所以返回入参是安全的。
//
// 判定写错会导致漏检（把"其实变了"判成"没变"），所以每条都配了单测。

// hasUpperASCII 判断是否含需要转小写的字符。
func hasUpperASCII(b []byte) bool {
	for _, c := range b {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// hasLowerASCII 判断是否含需要转大写的字符。
func hasLowerASCII(b []byte) bool {
	for _, c := range b {
		if c >= 'a' && c <= 'z' {
			return true
		}
	}
	return false
}

// hasByte 判断是否含某个字节。
func hasByte(b []byte, c byte) bool {
	for _, x := range b {
		if x == c {
			return true
		}
	}
	return false
}

// anyByte 判断是否含集合里任一字节。
func anyByte(b []byte, set string) bool {
	for _, x := range b {
		if strings.IndexByte(set, x) >= 0 {
			return true
		}
	}
	return false
}

// hasRepeatedByte 判断是否存在连续两个相同字节（压缩空白的必要条件）。
func hasRepeatedByte(b []byte, c byte) bool {
	for i := 1; i < len(b); i++ {
		if b[i] == c && b[i-1] == c {
			return true
		}
	}
	return false
}

// isTrimmed 判断首尾是否已经没有空白。
func isTrimmed(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	isSpace := func(c byte) bool {
		return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
	}
	return !isSpace(b[0]) && !isSpace(b[len(b)-1])
}

// needsCompressWhitespace 判断压缩空白是否真的会改变内容。
//
// 注意它不只是"有没有连续空格"：\t \n \r \v \f 本身就会被换成空格，
// 所以出现它们也必须真跑一遍。这个细节写错会导致漏检。
func needsCompressWhitespace(b []byte) bool {
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch c {
		case '\t', '\n', '\r', '\v', '\f':
			return true
		case ' ':
			if i > 0 && b[i-1] == ' ' {
				return true
			}
		}
	}
	return false
}

// hasCommentMarker 判断是否可能出现注释（removeComments/replaceComments 的必要条件）。
func hasCommentMarker(b []byte) bool {
	if hasByte(b, '#') {
		return true
	}
	for i := 1; i < len(b); i++ {
		if b[i] == '/' && b[i-1] == '/' {
			return true
		}
	}
	// "/*" 与 "--" 与 "<!--"
	if i := indexOf(b, "/*"); i >= 0 {
		return true
	}
	if i := indexOf(b, "--"); i >= 0 {
		return true
	}
	if i := indexOf(b, "<!"); i >= 0 {
		return true
	}
	return false
}

func indexOf(b []byte, s string) int {
	if len(s) == 0 || len(b) < len(s) {
		return -1
	}
	for i := 0; i+len(s) <= len(b); i++ {
		match := true
		for j := 0; j < len(s); j++ {
			if b[i+j] != s[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// looksBase64ish 判断是否可能被 base64 解码（快速排除，避免 DecodedLen 白白算一次）。
//
// **必须放行 `\r` 与 `\n`**：Go 的 base64 解码器会忽略换行，
// 而这里是"不通过就返回原值"的快速路径 —— 判错方向就是漏检
// 。
//
// 注意：这只是**排除**用，不是"能不能解码"的判断 —— 真正的解码失败仍然由
// 解码器返回错误、实现返回入参。判成 false 时必须保证解码一定失败，
// 所以长度不足或含非 base64 字符才算 false。
func looksBase64ish(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '=', c == '-', c == '_':
		case c == '\r', c == '\n': // Go 的解码器会忽略它们，快路径不能把它们当"非 base64"
		default:
			return false
		}
	}
	return true
}

// isHexString 判断是否全是十六进制字符（hex/sqlHex 解码的必要条件）。
func isHexString(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		_, ok := unhex(c)
		if !ok {
			return false
		}
	}
	return true
}

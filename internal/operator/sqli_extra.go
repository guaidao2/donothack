package operator

import (
	"strings"
)

// 本文件补两类 crackweb 实测打出来的 SQLi 指纹缺口。
//
// 背景（真实绕过，不是假想）：crackweb 1.6.4 对
// `?id=<base64({"uid":1,"ml":"1","id":"<payload>"})>` 报了两条：
//
//	[Critical] SQL injection (error-based)   Payload: '
//	[High]     SQL injection (boolean-based blind)  Payload: 1 AND 1=2
//
// 展开链路本身没问题（修好"展开结果没进 ARGS 合并视图"之后 UNION 形态已经能拦），
// 剩下的问题在**指纹覆盖**：
//
//  1. `1 AND 1=2` 是**矛盾式**，而原来的 tactology 判据只认恒真（`1=1`、`2>1`）——
//     攻击者用 `AND 1=2` 做布尔盲注（成立与否看响应差异），反而绕过了"只认恒真"的判据。
//  2. 单独的引号 `'` 是错误型注入的经典探测：原实现要求"引号 + 注释"或"引号 + 恒真"，
//     光一个引号什么也不命中。
//
// 误报侧的处理：
//   - 布尔比较要求 `and/or` 两侧是**数字或引号包起来的字面量**，正常文案里不会出现；
//   - 引号探测只认"整值就是引号"或"数字后紧跟引号"（`1'`）这种**语法性**用法，
//     `O'Brien`、`it's a nice day` 这类词内撇号一律不碰。
//
// 这两条与 ModSecurity CRS 的做法一致（CRS 对单独引号也是记分命中）。

// booleanComparison 识别布尔盲注的比较式：`and 1=2`、`or 2>1`、`and 'a'='b'`。
//
// 与 tautology 的区别：**不管真假**。攻击者用矛盾式做盲注，只认恒真就是漏。
func booleanComparison(s string) bool {
	for _, kw := range []string{" and ", " or ", "&&", "||"} {
		idx := 0
		for {
			i := strings.Index(s[idx:], kw)
			if i < 0 {
				break
			}
			rest := strings.TrimSpace(s[idx+i+len(kw):])
			if looksComparison(rest) {
				return true
			}
			idx += i + len(kw)
			if idx >= len(s) {
				break
			}
		}
	}
	return false
}

// looksComparison 判断开头是不是 `操作数 比较符 操作数`。
func looksComparison(rest string) bool {
	if len(rest) < 3 {
		return false
	}
	// 操作数一：数字、引号字面量、或 true/false/null
	var operandLen int
	switch {
	case rest[0] >= '0' && rest[0] <= '9':
		operandLen = 1
		for operandLen < len(rest) && (rest[operandLen] >= '0' && rest[operandLen] <= '9' ||
			rest[operandLen] == '.') {
			operandLen++
		}
	case rest[0] == '\'' || rest[0] == '"':
		q := rest[0]
		end := strings.IndexByte(rest[1:], q)
		if end < 0 {
			return false
		}
		operandLen = end + 2
	case strings.HasPrefix(rest, "true"), strings.HasPrefix(rest, "false"), strings.HasPrefix(rest, "null"):
		operandLen = 4
	default:
		return false
	}
	rest = strings.TrimSpace(rest[operandLen:])
	if rest == "" {
		return false
	}
	// 比较符（含 SQL 的 <>、!=、>=、<=）
	switch rest[0] {
	case '=', '<', '>', '!':
	default:
		return false
	}
	opLen := 1
	if len(rest) > 1 && (rest[1] == '=' || rest[0] == '<' && rest[1] == '>') {
		opLen = 2
	}
	rest = strings.TrimSpace(rest[opLen:])
	if rest == "" {
		return false
	}
	// 操作数二：数字、引号字面量、true/false/null
	switch {
	case rest[0] >= '0' && rest[0] <= '9':
		return true
	case rest[0] == '\'' || rest[0] == '"':
		q := rest[0]
		return strings.IndexByte(rest[1:], q) >= 0
	case strings.HasPrefix(rest, "true"), strings.HasPrefix(rest, "false"), strings.HasPrefix(rest, "null"):
		return true
	}
	return false
}

// quoteProbing 识别"语法性引号"：整值就是引号，或数字后紧跟引号。
//
// 为什么敢拦：`O'Brien`、`it's`、`"quoted phrase"` 里引号都在**词内或成对**，
// 而错误型注入探测发的是一个**孤零零的引号**（`'`）或 `1'` 这种数字+引号。
// 这一点与 ModSecurity CRS 的判断一致 —— 单独引号在 CRS 里也是记分命中。
func quoteProbing(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || len(t) > 8 {
		return false
	}
	// 整值只有引号：' / " / '' / \"
	onlyQuotes := true
	for i := 0; i < len(t); i++ {
		if t[i] != '\'' && t[i] != '"' && t[i] != '`' {
			onlyQuotes = false
			break
		}
	}
	if onlyQuotes {
		return true
	}
	// 数字后紧跟引号：1' / 42"
	i := 0
	for i < len(t) && t[i] >= '0' && t[i] <= '9' {
		i++
	}
	if i == 0 || i == len(t) {
		return false
	}
	switch t[i] {
	case '\'', '"', '`':
		// 引号后面只允许再跟引号（1''）
		for j := i; j < len(t); j++ {
			if t[j] != '\'' && t[j] != '"' && t[j] != '`' {
				return false
			}
		}
		return true
	}
	return false
}

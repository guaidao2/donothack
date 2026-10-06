package rules

import "strings"

// longestLiteralInPattern 从正则源码里提取**最长的一段字面量**。
//
// 为什么不能用 regexp 的 LiteralPrefix：那只能拿到**前缀**，
// 而真实规则里的正则大多不以字面量开头 ——
//
//	\bunion\b\s+select        → 前缀是空的，但 "union" 是安全字面量
//	<script[^>]*>             → 前缀 "<script" 能拿到 ✓
//	['")\]]\s*(or|and)\s+     → 前缀是空的，但 "or"、"and" 太短（<3）不该进预筛
//
// 拿不到字面量的规则只能每请求执行，预筛收益被拉低：
// 实测 59 条规则里，只取前缀时有 20 条（34%）退化成每请求执行，
// 取最长字面量后降到 11 条（18.6%）。
//
// 提取规则（保守优先，宁可少提也不能提错 —— 提错会导致漏检）：
//   - 普通字符逐个累积；
//   - `\.` 这类转义取被转义的字符本身；`\d\w\s\b\A\z\1` 是类别/锚点/反向引用，不算字面量；
//   - `.`、`[]`、`()`、`{}`、`|`、`^`、`$`、`*`、`+`、`?` 切断当前段；
//   - 被量词（`*`/`+`/`?`/`{`）修饰的**最后一个字符**可能不出现，所以整段丢掉末位字符；
//   - 字符类 `[...]` 整体跳过（里面的字符是择一的，不能当固定字面量）。
func longestLiteralInPattern(pat string) string {
	var best []byte
	var run []byte

	flush := func(quantified bool) {
		s := run
		if quantified && len(s) > 0 {
			s = s[:len(s)-1]
		}
		if len(s) > len(best) {
			best = append(best[:0], s...)
		}
		run = run[:0]
	}

	i := 0
	for i < len(pat) {
		c := pat[i]
		switch c {
		case '\\':
			if i+1 >= len(pat) {
				flush(false)
				i++
				continue
			}
			e := pat[i+1]
			if isRegexClassEscape(e) {
				flush(false)
			} else {
				run = append(run, e)
			}
			i += 2
		case '[':
			flush(false)
			// 跳过整个字符类（含转义）
			i++
			for i < len(pat) && pat[i] != ']' {
				if pat[i] == '\\' {
					i++
				}
				i++
			}
			if i < len(pat) {
				i++
			}
		case '.', '(', ')', '{', '}', '|', '^', '$':
			flush(false)
			i++
		case '*', '+', '?':
			// 量词：它修饰的是上一段的最后一个字符
			flush(true)
			i++
		default:
			run = append(run, c)
			i++
		}
	}
	flush(false)
	return string(best)
}

// isRegexClassEscape 判断 `\X` 是否是"类别/锚点/反向引用"而不是字面量。
func isRegexClassEscape(e byte) bool {
	switch e {
	case 'd', 'D', 'w', 'W', 's', 'S', 'b', 'B', 'A', 'z', 'Z', 'p', 'P', 'Q', 'E':
		return true
	}
	return e >= '0' && e <= '9' // \1 反向引用
}

// regexLiteralCandidate 判断从正则里提的字面量是否够格进预筛。
func regexLiteralCandidate(pat string, minLen int) ([]byte, bool) {
	lit := longestLiteralInPattern(pat)
	if len(lit) < minLen {
		return nil, false
	}
	// 全空白或全是同一字符的字面量没有区分度
	if strings.TrimSpace(lit) == "" {
		return nil, false
	}
	return []byte(lit), true
}

// regexLiteralCandidateSafe 是带安全判据的版本：不合规就当作"无法预筛"。
//
// **这里错了会直接造成漏检**，因为预筛语义是"没命中字面量就跳过这条规则"。
// 要能预筛，必须满足"正则匹配 ⇒ 这个字面量必然出现在输入里"。两种形态会打破它：
//
//  1. 交替 `|`：`\.(?:git|svn|hg)/` 可以只靠 "git" 匹配。而我们只能提一个最长
//     字面量（比如 "git-credentials"），输入里只有 ".git" 时预筛就会跳过这条规则 ——
//     实测 SCAN-2003（`\.(git|svn|...)/`）与 UPLOAD-1001（多扩展名交替）就栽在这上面。
//  2. 可选的组 `(...)?` / `(...)*` / `{0,n}`：组内字面量可能**整体**不出现，
//     不只是"少最后一个字符"。
//
// 结论：宁可让规则每请求执行（有成本但正确），也不接受预筛静默漏检。
func regexLiteralCandidateSafe(pat string, minLen int) ([]byte, bool) {
	if !regexIsPrefilterSafe(pat) {
		return nil, false
	}
	return regexLiteralCandidate(pat, minLen)
}

// regexIsPrefilterSafe 判断这个正则能否安全地用"单个字面量"做预筛。
func regexIsPrefilterSafe(pat string) bool {
	for i := 0; i < len(pat); i++ {
		switch pat[i] {
		case '\\':
			i++ // 跳过被转义的下一个字符
		case '[':
			i++
			for i < len(pat) && pat[i] != ']' {
				if pat[i] == '\\' {
					i++
				}
				i++
			}
		case '|':
			return false
		case ')':
			// 组被量词修饰 → 组内字面量可能整体缺失
			j := i + 1
			for j < len(pat) && (pat[j] == ' ' || pat[j] == '\t') {
				j++
			}
			if j < len(pat) {
				switch pat[j] {
				case '*', '?':
					return false
				case '{':
					if j+1 < len(pat) && pat[j+1] == '0' {
						return false
					}
				}
			}
		case '{':
			if i+1 < len(pat) && pat[i+1] == '0' {
				return false
			}
		}
	}
	return true
}

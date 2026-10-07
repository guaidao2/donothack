package operator

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"donothack/internal/kv"
)

// 语义算子。
//
// 为什么要有它们：纯正则打不动 crackweb 这类"推导 payload"的扫描器 ——
// 它把种子按代数做结构改写与编码，正则的覆盖面必然跟不上。
// 语义算子的思路是**看形状**而不是看字面：
//   - detectSQLi  看的是"引号 + 关键字 + 运算符"的组合形态
//   - detectXSS   看的是"标签/伪协议/事件处理器"的上下文
//   - entropy     看的是"这段文本像不像随机串"（密钥、混淆载荷）
//
// 诚实说明：detectSQLi 是**精简版**（不是完整的 libinjection 移植），
// 目标是把常见注入形态判死，同时不误伤带单引号的正常文案。
// 它的边界写在 ，误报样本进语料回归。
func registerSemanticOps() {
	Register("detectSQLi", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		minLen, ok := p.Int("min_fingerprint_len")
		if !ok {
			minLen = 8
		}
		if minLen < 0 {
			return nil, errors.New("min_fingerprint_len 不能为负")
		}
		// 指纹过滤（见 sqliOp.Eval 的说明）。名字写错在**编译期**报错 ——
		// 与"未知参数要拒绝"同一条纪律：静默失效比启动失败难查得多。
		only, err := fingerprintSet(p.Strings("fingerprints"))
		if err != nil {
			return nil, err
		}
		exclude, err := fingerprintSet(p.Strings("exclude_fingerprints"))
		if err != nil {
			return nil, err
		}
		if only != nil && exclude != nil {
			return nil, errors.New("fingerprints 与 exclude_fingerprints 只能用一个（两个都写语义会互相打架）")
		}
		return sqliOp{minLen: minLen, only: only, exclude: exclude}, nil
	})

	Register("detectXSS", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		minLen, ok := p.Int("min_fingerprint_len")
		if !ok {
			minLen = 6
		}
		return xssOp{minLen: minLen}, nil
	})

	Register("detectPathTraversal", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		minDepth, ok := p.Int("min_depth")
		if !ok {
			minDepth = 1
		}
		if minDepth < 1 {
			return nil, errors.New("min_depth 至少为 1")
		}
		return pathTraversalOp{minDepth: minDepth}, nil
	})

	Register("containsShellChars", func(_ *CompileCtx, _ kv.Params) (Compiled, error) {
		return shellCharsOp{}, nil
	})

	Register("isWebshellContent", func(_ *CompileCtx, _ kv.Params) (Compiled, error) {
		return webshellOp{}, nil
	})

	Register("entropy", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		minBits, ok := p.Float("min_bits")
		if !ok {
			minBits = 4.0
		}
		minLen, ok := p.Int("min_len")
		if !ok {
			minLen = 20
		}
		if minBits <= 0 || minBits > 8 {
			return nil, errors.New("min_bits 必须在 (0, 8] 之间")
		}
		if minLen <= 0 {
			return nil, errors.New("min_len 必须为正")
		}
		return entropyOp{minBits: minBits, minLen: minLen}, nil
	})

	Register("luhn", func(_ *CompileCtx, _ kv.Params) (Compiled, error) {
		return luhnOp{}, nil
	})
}

// ---------------------------------------------------------------- SQLi

// sqliFingerprintNames 是 detectSQLi 能返回的全部指纹名。
//
// 两处用它：① 编译期校验规则里写的指纹名（写错就直接拒绝加载，
// 而不是静默失效）；② 文档与测试的单一事实来源。
var sqliFingerprintNames = []string{
	"union select",
	"time-based",
	"metadata table",
	"file/exec primitive",
	"stacked query",
	"boolean comparison",
	"subquery in boolean context",
	"quote + comment",
	"boolean tautology",
	"quote probing",
	"boolean expression",
}

type sqliOp struct {
	minLen  int
	only    map[string]bool // 非 nil = 只看这些指纹
	exclude map[string]bool // 命中这些指纹就当作没命中
}

func (o sqliOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	fp := sqliFingerprint(in, o.minLen)
	if fp == "" {
		return Result{}, nil
	}
	// 指纹过滤：让"强弱信号"能分成两条不同分值的规则。
	//
	// 为什么需要它：`quote probing`（值本身就是引号 / `1'`）是**弱信号** ——
	// 搜索框里搜一个引号字符是正常行为，它单独命中就够阈值的话，
	// 就成了设计文档明确要避免的"一个单引号封站"。
	// 而 `union select`、`boolean comparison` 这些是强特征，该单独拦。
	// 两者共用同一个算子，所以过滤必须由参数来做。
	if o.only != nil && !o.only[fp] {
		return Result{}, nil
	}
	if o.exclude != nil && o.exclude[fp] {
		return Result{}, nil
	}
	return Result{Matched: true, Detail: "sqli fingerprint: " + fp}, nil
}

// fingerprintSet 把规则里写的指纹名列表转成集合；空列表返回 nil（表示不过滤）。
func fingerprintSet(names []string) (map[string]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		n = strings.TrimSpace(strings.ToLower(n))
		if n == "" {
			continue
		}
		if !isKnownFingerprint(n) {
			return nil, fmt.Errorf("未知的 SQL 注入指纹 %q（可选：%s）",
				n, strings.Join(sqliFingerprintNames, "、"))
		}
		out[n] = true
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func isKnownFingerprint(n string) bool {
	for _, k := range sqliFingerprintNames {
		if k == n {
			return true
		}
	}
	return false
}

// sqliFingerprint 返回命中的指纹名，空串表示没命中。
func sqliFingerprint(in []byte, minLen int) string {
	if len(in) == 0 {
		return ""
	}
	s := lowerASCII(in)
	s = collapseSpaces(s)
	hasQuote := strings.ContainsAny(s, `'"`)

	// 1) 强特征：与长度无关
	if wordPair(s, "union", "select") {
		return "union select"
	}
	if containsAnyOf(s, "sleep(", "benchmark(", "pg_sleep(", "waitfor delay", "dbms_pipe.receive_message") {
		return "time-based"
	}
	if containsAnyOf(s, "information_schema", "mysql.user", "sys.objects", "sys.tables",
		"sys.columns", "pg_catalog", "all_tables", "sqlite_master") {
		return "metadata table"
	}
	if containsAnyOf(s, "into outfile", "into dumpfile", "load_file(", "xp_cmdshell", "sp_executesql") {
		return "file/exec primitive"
	}
	if stackedQuery(s) {
		return "stacked query"
	}

	// 1.5) 布尔比较：**不管是恒真还是矛盾**。
	// 攻击者做布尔盲注用的是矛盾式（`1 AND 1=2`），只认恒真就成了漏检。
	if booleanComparison(s) {
		return "boolean comparison"
	}

	// 2) 需要引号上下文的特征
	if hasQuote {
		if subqueryFingerprint(s) {
			return "subquery in boolean context"
		}
		if quoteThenComment(s) {
			return "quote + comment"
		}
		if tautology(s) {
			return "boolean tautology"
		}
	}

	// 2.5) 语法性引号（错误型注入的探测形态）：整值就是引号，或 `1'`。
	// 放在引号上下文之后、弱特征之前 —— 它不依赖长度。
	if quoteProbing(s) {
		return "quote probing"
	}

	// 3) 弱特征：只在输入足够长时才认（避免 "1=1" 这类短文本误报）
	if len(s) >= minLen {
		// "and (select ...)" 这种子查询注入形态在正常文案里不会出现，
		// 所以没有引号也认。crackweb 的布尔/联合注入就会走这条。
		if subqueryFingerprint(s) {
			return "subquery in boolean context"
		}
		if tautology(s) {
			return "boolean tautology"
		}
		if containsAnyOf(s, " or ", " and ") && strings.Contains(s, "=") && hasQuote {
			return "boolean expression"
		}
		if booleanComparison(s) {
			return "boolean comparison"
		}
	}
	return ""
}

// subqueryFingerprint 识别 "and (select ...)" / "or (select ...)" 形态。
//
// 这是自测抓出来的真实缺口：`1' and (select count(*) from users)>0--`
// 在去掉注释之后既没有恒真比较、也没有 union，原来的指纹漏掉了它。
func subqueryFingerprint(s string) bool {
	for _, kw := range []string{"and (", "or (", "and(", "or(", "&&(", "||("} {
		idx := 0
		for {
			i := strings.Index(s[idx:], kw)
			if i < 0 {
				break
			}
			rest := s[idx+i+len(kw):]
			if len(rest) > 32 {
				rest = rest[:32]
			}
			if strings.Contains(rest, "select") || strings.Contains(rest, "case when") {
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

func tautology(s string) bool {
	// or/and 后面跟恒真比较
	for _, kw := range []string{" or ", " and ", "||", "&&"} {
		idx := 0
		for {
			i := strings.Index(s[idx:], kw)
			if i < 0 {
				break
			}
			rest := strings.TrimSpace(s[idx+i+len(kw):])
			if looksTautology(rest) {
				return true
			}
			idx += i + len(kw)
			if idx >= len(s) {
				break
			}
		}
	}
	// 直接以恒真比较开头
	return looksTautology(strings.TrimSpace(s))
}

func looksTautology(rest string) bool {
	// 1=1 / 2>1 / 'a'='a' / "x"="x"
	pairs := []string{"1=1", "2>1", "1<2", "'1'='1", `"1"="1`, "'a'='a'", `"a"="a`, "true", "1 like 1"}
	for _, p := range pairs {
		if strings.HasPrefix(rest, p) {
			return true
		}
	}
	return false
}

func quoteThenComment(s string) bool {
	// **先做一次 O(n) 的必要条件判断**。
	//
	// 下面的循环对**每个**引号都要做最多 192 字节的子串搜索，实测 64 KiB 的
	// 纯引号值要 1.36 ms —— 而 `MaxInspectBody` 是 512 KiB，也就是单条规则
	// 能吃 11 ms CPU。所以先用一次线性扫描把"压根没有注释标记"的值排除掉：
	// 整串里没有 `--` / `/*` / `#` 时，下面那个循环不可能返回 true。
	if !strings.Contains(s, "--") && !strings.Contains(s, "/*") && !strings.ContainsRune(s, '#') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '\'' && s[i] != '"' {
			continue
		}
		rest := s[i+1:]
		if len(rest) > 64 {
			rest = rest[:64]
		}
		if strings.Contains(rest, "--") || strings.HasPrefix(strings.TrimSpace(rest), "#") ||
			strings.Contains(rest, "/*") {
			return true
		}
	}
	return false
}

func stackedQuery(s string) bool {
	// 同样的 O(n) 前置判断：整串里连一个关键字都没有时，
	// 下面按 `;` 展开的循环不可能命中。**这个尤其重要** ——
	// 它每个分号都做一次 TrimSpace 与 10 次前缀比较，
	// 512 KiB 的分号串就是 O(n²)，比上面那个更狠。
	if !containsAnyKeyword(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != ';' {
			continue
		}
		rest := strings.TrimSpace(s[i+1:])
		for _, kw := range stackedKeywords {
			if hasKeywordPrefix(rest, kw) {
				return true
			}
		}
	}
	return false
}

// hasKeywordPrefix 判断 rest 是否以关键字开头，比对时把 `+` 与空格视为等价。
//
// 为什么需要：查询串里的 `+` 代表空格，但 **REQUEST_URI 保留的是原始串**（`+` 没被解成空格）。
// 于是 `?id=1;DROP+TABLE+users` 走到这里，分号后面拿到的是 `drop+table+users`，
// 用 `strings.HasPrefix(rest, "drop ")` 配不上 —— 实测这条堆叠注入曾整条漏检。
// 只比前 len(kw) 个字节，零分配。
func hasKeywordPrefix(rest, kw string) bool {
	if len(rest) < len(kw) {
		return false
	}
	for i := 0; i < len(kw); i++ {
		c := rest[i]
		if c == '+' {
			c = ' '
		}
		if c != kw[i] {
			return false
		}
	}
	return true
}

// stackedKeywords 是堆叠查询的关键字表（顺序即匹配顺序）。
var stackedKeywords = []string{
	"select ", "insert ", "update ", "delete ", "drop ", "create ", "alter ", "exec ", "shutdown",
}

// containsAnyKeyword 判断串里是否**可能出现**任何一个堆叠查询关键字。
//
// 这是必要条件的近似（只看关键字本身、不看它是否紧跟分号），
// 放过的多、漏掉的没有 —— 对"提前退出"来说方向必须是这样：宁可多跑一遍完整循环，
// 也不能因为前置判断而漏检。
func containsAnyKeyword(s string) bool {
	for _, kw := range stackedKeywords {
		// 关键字表里都带尾随空格；这里也检查去空格形式，
		// 避免 `;select`（无空格）这种形态被前置判断误杀。
		if strings.Contains(s, kw) || strings.Contains(s, strings.TrimSuffix(kw, " ")) {
			return true
		}
	}
	return false
}

func containsAnyOf(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// wordPair 判断两个词是否按顺序出现（作为独立词）。
func wordPair(s, a, b string) bool {
	ia := indexWord(s, a)
	if ia < 0 {
		return false
	}
	rest := s[ia+len(a):]
	if len(rest) > 40 {
		rest = rest[:40]
	}
	return indexWord(rest, b) >= 0
}

func indexWord(s, w string) int {
	idx := 0
	for {
		i := strings.Index(s[idx:], w)
		if i < 0 {
			return -1
		}
		pos := idx + i
		before := pos == 0 || !isWordByte(s[pos-1])
		afterPos := pos + len(w)
		after := afterPos >= len(s) || !isWordByte(s[afterPos])
		if before && after {
			return pos
		}
		idx = pos + 1
		if idx >= len(s) {
			return -1
		}
	}
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func lowerASCII(in []byte) string {
	out := make([]byte, len(in))
	for i, c := range in {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// collapseSpaces 折叠连续空白。
//
// **先判断有没有要折叠的**：`strings.Builder.Grow` 是无条件分配的，
// 而正常请求里的值绝大多数根本不需要折叠（没 TAB、没有连续空格）——
// 于是每个请求白搭几次分配。实测这一处占热路径分配的 3/次。
func collapseSpaces(s string) string {
	if !needsCollapse(s) {
		return s
	}
	var sb strings.Builder
	sb.Grow(len(s))
	prev := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		isWS := c == ' ' || c == '\t' || c == '\n' || c == '\r'
		if isWS {
			if prev {
				continue
			}
			sb.WriteByte(' ')
			prev = true
			continue
		}
		sb.WriteByte(c)
		prev = false
	}
	return sb.String()
}

// needsCollapse 判断是否存在需要折叠的空白。
//
// 两类：连续空白，以及 TAB/换行（它们会被折成单个空格，即使只有一个）。
func needsCollapse(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\t', '\n', '\r':
			return true
		case ' ':
			if i > 0 && s[i-1] == ' ' {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------- XSS

type xssOp struct{ minLen int }

func (o xssOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	s := lowerASCII(in)
	if len(s) < 4 {
		return Result{}, nil
	}

	if strings.Contains(s, "<script") {
		return Result{Matched: true, Detail: "xss: script tag"}, nil
	}
	for _, scheme := range []string{"javascript:", "vbscript:", "data:text/html", "data:application/xhtml"} {
		if strings.Contains(s, scheme) {
			return Result{Matched: true, Detail: "xss: scheme " + strings.TrimSuffix(scheme, ":")}, nil
		}
	}
	if strings.Contains(s, "expression(") && strings.Contains(s, "(") {
		return Result{Matched: true, Detail: "xss: css expression"}, nil
	}
	// 事件处理器必须与标签上下文同时出现：光有 "onerror=" 是正常文案
	if tagStart := strings.IndexByte(s, '<'); tagStart >= 0 {
		if handler := eventHandlerNear(s, tagStart); handler != "" {
			return Result{Matched: true, Detail: "xss: event handler " + handler}, nil
		}
	}
	if strings.Contains(s, "document.cookie") || strings.Contains(s, "document.write(") {
		return Result{Matched: true, Detail: "xss: dom sink"}, nil
	}
	return Result{}, nil
}

// eventHandlerNear 在 '<' 之后、标签结束之前找 on* 事件属性。
//
// 两条收紧条件（都是为了压误报）：
//  1. '<' 后面必须紧跟字母（是标签名），所以 "3 < 5 onerror = x" 不算。
//  2. 事件属性必须出现在同一个标签内（'<' 与 '>' 之间），不能跨标签乱找。
func eventHandlerNear(s string, lt int) string {
	if lt+1 >= len(s) {
		return ""
	}
	c := s[lt+1]
	if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		return ""
	}
	end := lt + 128
	if end > len(s) {
		end = len(s)
	}
	seg := s[lt:end]
	if gt := strings.IndexByte(seg, '>'); gt >= 0 {
		seg = seg[:gt]
	}
	for _, h := range []string{
		"onerror", "onload", "onclick", "onfocus", "onblur", "onmouseover", "onmouseenter",
		"onsubmit", "onchange", "onstart", "ontoggle", "onanimationstart", "onscroll",
	} {
		i := strings.Index(seg, h)
		if i < 0 {
			continue
		}
		// 前面必须是空白（属性边界），避免 "microphone" 里的 "phone" 之类误命中
		if i > 0 {
			prev := seg[i-1]
			if prev != ' ' && prev != '\t' && prev != '\n' && prev != '/' && prev != '"' && prev != '\'' {
				continue
			}
		}
		rest := strings.TrimLeft(seg[i+len(h):], " \t\r\n")
		if strings.HasPrefix(rest, "=") {
			return h
		}
	}
	return ""
}

// ---------------------------------------------------------------- 路径穿越

type pathTraversalOp struct{ minDepth int }

func (o pathTraversalOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	s := lowerASCII(in)
	depth := 0
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '.' && s[i+1] == '.' && (s[i+2] == '/' || s[i+2] == '\\') {
			depth++
			i += 2
		}
	}
	// 代码里直接写敏感文件路径也算（LFI 的另一种形态）
	wrappers := []string{"php://", "file://", "expect://", "phar://", "zip://", "data://"}
	sensitive := []string{"/etc/passwd", "/etc/shadow", "/proc/self/environ", `c:\windows\win.ini`, "boot.ini", "web-inf/web.xml"}
	if depth >= o.minDepth {
		return Result{Matched: true, Detail: "path traversal"}, nil
	}
	for _, w := range wrappers {
		if strings.Contains(s, w) {
			return Result{Matched: true, Detail: "lfi wrapper " + strings.TrimSuffix(w, "://")}, nil
		}
	}
	for _, p := range sensitive {
		if strings.Contains(s, p) {
			return Result{Matched: true, Detail: "sensitive path"}, nil
		}
	}
	return Result{}, nil
}

// ---------------------------------------------------------------- 命令注入

type shellCharsOp struct{}

// shellCommands 是"分隔符后面出现就立案"的命令名表。
//
// 这份表**不可能列全**（第三方测评指出过：`;pwd`、`;echo`、`;w` 以前都不在表里），
// 所以它的定位是"高置信度信号"，不是唯一判据：
//   - 表里的命令 + 分隔符 → 直接拦（RCE-6001/6003）；
//   - 表外的词 + 分隔符 + 路径/参数 → 结构判定兜底（RCE-6017，记分叠加）。
//
// 新命令往这里加就行，不要再靠一条条加规则。
var shellCommands = []string{
	// 信息收集
	"id", "whoami", "uname", "hostname", "w", "who", "ps", "pwd", "env", "printenv",
	"date", "uptime", "last", "lastlog", "df", "du", "free", "top", "lsof", "ss",
	"ifconfig", "ipconfig", "ip", "arp", "route", "netstat", "systeminfo", "tasklist",
	"nslookup", "dig", "host", "ping", "traceroute", "tracert", "nmap", "nc", "ncat",
	"telnet", "ftp", "ssh", "scp", "rsync", "curl", "wget",
	// 文件与内容
	"cat", "tac", "head", "tail", "more", "less", "ls", "dir", "find", "locate",
	"grep", "egrep", "fgrep", "awk", "sed", "cut", "sort", "uniq", "wc", "strings",
	"xxd", "od", "base64", "md5sum", "sha1sum", "sha256sum", "cp", "mv", "rm",
	"mkdir", "rmdir", "touch", "ln", "chmod", "chown", "chgrp", "tar", "zip", "unzip",
	"gzip", "gunzip", "bzip2", "7z", "rsync",
	// 执行与解释器
	"sh", "bash", "dash", "zsh", "ksh", "csh", "ash", "busybox", "python", "python3",
	"perl", "ruby", "php", "node", "nodejs", "lua", "java", "gcc", "g++", "make",
	"cmd", "cmd.exe", "powershell", "pwsh", "cscript", "wscript", "mshta", "rundll32",
	"regsvr32", "certutil", "bitsadmin", "wmic", "schtasks", "reg", "net", "sc",
	// 进程与服务控制
	"kill", "killall", "pkill", "sudo", "su", "systemctl", "service", "crontab", "at",
	"mount", "umount", "insmod", "modprobe", "docker", "kubectl", "git", "vim", "vi",
	"nano", "emacs", "echo", "printf", "tee", "xargs", "eval", "exec", "source", "export",
}

// shellArgFollows 判断命令名后面是不是"真的到了命令边界"，
// 而不是命令名的一部分（`ls` 不能匹配 `lsass`、`id` 不能匹配 `identity`）。
// trimPathPrefix 去掉命令名前的路径前缀（`/bin/id` -> `id`）。
// 只处理以 `/` 开头的一段，避免动到参数里的普通文本。
func trimPathPrefix(s string) string {
	if len(s) == 0 || s[0] != '/' {
		return s
	}
	if k := strings.LastIndexByte(s, '/'); k >= 0 && k+1 < len(s) {
		return s[k+1:]
	}
	return s
}

func shellArgFollows(after string) bool {
	if after == "" {
		return true
	}
	switch after[0] {
	// `+` 也算：它在前端/后端的表单与 Cookie 解码里代表空格
	// （PHP 的 urldecode 就解 `+`），所以 `;cat+/etc/passwd` 在 Cookie/头里是成立的分隔。
	case ' ', '\t', '+', '-', ';', '|', '&', '\n', '\r':
		return true
	}
	return false
}

// looksLikeCommandLine 是**换行分隔**的额外收紧条件。
//
// 为什么只有换行需要它：`;`、`|`、`&&` 在正常文案里基本不出现，
// 而换行到处都是 —— 一段多行文本里"某行以 cat/sh/id 开头"完全可能。
// 所以换行后跟命令名时，还要看它像不像一条**命令**：
// 命令到此为止，或者参数里有路径、选项、变量、重定向这类 shell 痕迹。
func looksLikeCommandLine(after string) bool {
	if after == "" {
		return true
	}
	switch after[0] {
	case ';', '|', '&':
		return true
	}
	arg := strings.TrimLeft(after, " \t+")
	if arg == "" {
		return true
	}
	if len(arg) > 200 {
		arg = arg[:200]
	}
	return strings.ContainsAny(arg, "/-$`<>")
}

func (o shellCharsOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	s := lowerASCII(in)
	// $(...) 与反引号：内容非空即算（这是命令替换的形态本身）
	if i := strings.Index(s, "$("); i >= 0 {
		if strings.IndexByte(s[i+2:], ')') > 0 {
			return Result{Matched: true, Detail: "command substitution $()"}, nil
		}
	}
	if strings.Count(s, "`") >= 2 {
		return Result{Matched: true, Detail: "command substitution backtick"}, nil
	}
	// 分隔符 + 命令名
	//
	// `\n` / `\r` 单独收紧：它们确实是换行分隔的典型形态（`127.0.0.1\nid`），
	// 但在**正常多行文本**里也会出现 —— 一行以 `cat photos are cute` 开头时，
	// 光看"换行 + 命令名"就会误报。所以换行这种分隔符额外要求后面
	// 要么命令到串尾，要么参数里带 shell 痕迹（路径/选项/变量/重定向）。
	for i := 0; i < len(s); i++ {
		c := s[i]
		hardSep := c == ';' || c == '|' || c == '&'
		newlineSep := c == '\n' || c == '\r'
		if !hardSep && !newlineSep {
			continue
		}
		rest := strings.TrimLeft(s[i+1:], " \t")
		// 命令名前面可能带路径：`/bin/hostname`、`/usr/bin/id`（“分隔符后紧跟
		// 命令名”的假设会被这种写法破坏）。先剥掉最后一段路径再比命令名。
		rest = trimPathPrefix(rest)
		for _, cmd := range shellCommands {
			if !strings.HasPrefix(rest, cmd) {
				continue
			}
			after := rest[len(cmd):]
			if !shellArgFollows(after) {
				continue
			}
			if newlineSep && !looksLikeCommandLine(after) {
				continue
			}
			return Result{Matched: true, Detail: "command after separator: " + cmd}, nil
		}
	}
	// 重定向到路径
	if strings.Contains(s, "> /") || strings.Contains(s, ">> /") || strings.Contains(s, "> /etc") {
		return Result{Matched: true, Detail: "redirect to path"}, nil
	}
	// 远程下载
	if strings.HasPrefix(strings.TrimSpace(s), "wget http") || strings.HasPrefix(strings.TrimSpace(s), "curl http") ||
		strings.Contains(s, " -o /") || strings.Contains(s, " --output ") {
		return Result{Matched: true, Detail: "remote download"}, nil
	}
	return Result{}, nil
}

// ---------------------------------------------------------------- Webshell

type webshellOp struct{}

var webShellFuncs = []string{
	"eval(", "assert(", "system(", "exec(", "passthru(", "shell_exec(", "popen(",
	"proc_open(", "base64_decode(", "create_function(", "call_user_func(", "preg_replace(",
}

var webShellVars = []string{"$_get", "$_post", "$_request", "$_cookie", "$_server", "$_files", "request.form", "request.query", "runtime.getruntime().exec"}

func (o webshellOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	s := lowerASCII(in)
	hasFunc := ""
	for _, f := range webShellFuncs {
		if strings.Contains(s, f) {
			hasFunc = strings.TrimSuffix(f, "(")
			break
		}
	}
	if hasFunc == "" {
		if strings.Contains(s, "<%@") || strings.Contains(s, "<jsp:") {
			return Result{Matched: true, Detail: "webshell: jsp tag"}, nil
		}
		return Result{}, nil
	}
	for _, v := range webShellVars {
		if strings.Contains(s, v) {
			return Result{Matched: true, Detail: "webshell: " + hasFunc + " + 用户输入"}, nil
		}
	}
	// 只有函数调用没有变量源：交给 entropy 或其它规则，不在这里单独立案（降误报）
	_ = hasFunc
	return Result{}, nil
}

// ---------------------------------------------------------------- 熵与卡号

type entropyOp struct {
	minBits float64
	minLen  int
}

func (o entropyOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	if len(in) < o.minLen {
		return Result{}, nil
	}
	// 只对"看起来像不可打印/随机"的内容有意义；纯重复字符的熵为 0，自然不会命中。
	e := shannonEntropy(in)
	if e >= o.minBits {
		return Result{Matched: true, Detail: "high entropy"}, nil
	}
	return Result{}, nil
}

func shannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var e float64
	n := float64(len(b))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

type luhnOp struct{}

func (o luhnOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	digits := make([]int, 0, 24)
	flush := func() bool {
		if len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits) {
			return true
		}
		digits = digits[:0]
		return false
	}
	for _, c := range in {
		switch {
		case c >= '0' && c <= '9':
			digits = append(digits, int(c-'0'))
		case c == ' ' || c == '-' || c == '.':
			// 分隔符：跳过，但超长序列要切断
			if len(digits) > 19 {
				digits = digits[:0]
			}
		default:
			if flush() {
				return Result{Matched: true, Detail: "luhn: 卡号形态"}, nil
			}
		}
	}
	if flush() {
		return Result{Matched: true, Detail: "luhn: 卡号形态"}, nil
	}
	return Result{}, nil
}

func luhnValid(d []int) bool {
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		v := d[i]
		if double {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		double = !double
	}
	return sum%10 == 0
}

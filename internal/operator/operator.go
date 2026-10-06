// Package operator 实现规则里的匹配算子（docs/RULES.md §7）。
//
// 关键设计：算子分**编译期**与**运行期**两段。
//
//	Compile(params) (Compiled, error)   ← 规则加载时执行一次
//	Compiled.Eval(ctx, in) (Result, error) ← 每个请求执行
//
// 这样正则只编译一次、Aho-Corasick 只构建一次、未知参数在**加载期**就报错，
// 而不是等真实流量打上来才发现规则写错了。运行期的算子实例必须并发安全
// （被所有请求共享）。
package operator

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"donothack/internal/ac"
	"donothack/internal/kv"
	"donothack/internal/tx"
)

// EvalCtx 是求值上下文。
type EvalCtx struct {
	TxID   string
	RuleID string
	Phase  tx.Phase
}

// Capture 是一次命名捕获（回填到审计与 tx.Attrs）。
type Capture struct {
	Name  string
	Value []byte
}

// Result 是算子求值结果。
type Result struct {
	Matched  bool
	Captures []Capture
	// Detail 是给审计用的**可读说明**，绝不放 payload 原文。
	Detail string
}

// Compiled 是编译后的算子。
type Compiled interface {
	Eval(ctx *EvalCtx, in []byte) (Result, error)
}

// CompileCtx 携带编译期的上下文（目前只有嵌套深度，用于限制逻辑组合的层数）。
type CompileCtx struct {
	Depth int
}

// Compiler 在规则加载期把参数编译成可复用的算子实例。
type Compiler func(cc *CompileCtx, params kv.Params) (Compiled, error)

// maxCombineDepth 是逻辑组合的最大嵌套层数。规则集失控往往从
// "allOf 里套 anyOf 再套 not" 开始，所以这里硬性封顶。
const maxCombineDepth = 4

var registry = map[string]Compiler{}

// Register 注册算子。重名 panic（编译期错误必须在启动时炸出来）。
func Register(name string, c Compiler) {
	if _, dup := registry[name]; dup {
		panic("operator: 重复注册 " + name)
	}
	registry[name] = c
}

// Compile 编译一个算子。
func Compile(name string, params kv.Params) (Compiled, error) {
	return compileWith(name, params, &CompileCtx{})
}

func compileWith(name string, params kv.Params, cc *CompileCtx) (Compiled, error) {
	c, ok := registry[name]
	if !ok {
		if s := Suggestion(name); s != "" {
			return nil, fmt.Errorf("未知算子 %q（是否想写 %q？）", name, s)
		}
		return nil, fmt.Errorf("未知算子 %q（可用算子见 docs/RULES.md §7）", name)
	}
	if cc.Depth > maxCombineDepth {
		return nil, fmt.Errorf("算子组合嵌套超过 %d 层", maxCombineDepth)
	}
	op, err := c(cc, params)
	if err != nil {
		return nil, fmt.Errorf("算子 %s 参数有误：%w", name, err)
	}
	return op, nil
}

// Exists 判断算子是否已注册。
func Exists(name string) bool {
	_, ok := registry[name]
	return ok
}

// Names 返回全部算子名。
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
	lower := strings.ToLower(name)
	for _, n := range Names() {
		d := editDistance(lower, strings.ToLower(n))
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
			m := cur[j-1] + 1
			if v := prev[j] + 1; v < m {
				m = v
			}
			if v := prev[j-1] + cost; v < m {
				m = v
			}
			cur[j] = m
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

// fileBase 是 pmFromFile / ipMatchFromFile 的基准目录，由配置注入。
var fileBase = "."

// SetFileBase 设置规则文件里引用的外部名单的基准目录。
func SetFileBase(dir string) {
	if dir != "" {
		fileBase = dir
	}
}

func resolveFile(name string) (string, error) {
	clean := filepath.Clean(name)
	if filepath.IsAbs(clean) {
		return clean, nil
	}
	// 不允许用 .. 逃出基准目录
	if strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("名单路径不允许越出基准目录：%q", name)
	}
	return filepath.Join(fileBase, clean), nil
}

func loadLines(name string) ([][]byte, error) {
	p, err := resolveFile(name)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("读取名单文件失败：%w", err)
	}
	var out [][]byte
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, []byte(line))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("名单文件 %s 里没有任何有效条目", name)
	}
	return out, nil
}

// ---------------------------------------------------------------- 字符串算子

type eqOp struct{ v []byte }

func (o eqOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	return Result{Matched: string(in) == string(o.v), Detail: "eq"}, nil
}

type eqIgnoreCaseOp struct{ v string }

func (o eqIgnoreCaseOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	return Result{Matched: strings.EqualFold(string(in), o.v), Detail: "eqIgnoreCase"}, nil
}

type containsOp struct{ v []byte }

func (o containsOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	return Result{Matched: bytesContains(in, o.v), Detail: "contains"}, nil
}

type containsAnyOp struct{ vs [][]byte }

func (o containsAnyOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	for _, v := range o.vs {
		if bytesContains(in, v) {
			return Result{Matched: true, Detail: "containsAny"}, nil
		}
	}
	return Result{}, nil
}

type prefixOp struct {
	v      []byte
	suffix bool
}

func (o prefixOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	if o.suffix {
		return Result{Matched: bytesHasSuffix(in, o.v), Detail: "endsWith"}, nil
	}
	return Result{Matched: bytesHasPrefix(in, o.v), Detail: "startsWith"}, nil
}

type regexOp struct {
	re      *regexp.Regexp
	capture bool
	pattern string
}

func (o regexOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	m := o.re.FindSubmatch(in)
	if m == nil {
		return Result{}, nil
	}
	res := Result{Matched: true, Detail: "regex"}
	if o.capture {
		names := o.re.SubexpNames()
		for i := 1; i < len(m); i++ {
			name := ""
			if i < len(names) {
				name = names[i]
			}
			res.Captures = append(res.Captures, Capture{Name: name, Value: m[i]})
		}
	}
	return res, nil
}

type pmOp struct {
	m        *ac.Matcher
	matchAll bool
	patterns []string
}

func (o pmOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	if !o.matchAll {
		return Result{Matched: o.m.MatchAny(in), Detail: "pm"}, nil
	}
	seen := make(map[int32]struct{}, len(o.patterns))
	o.m.Scan(in, func(id int32, _ int) bool {
		seen[id] = struct{}{}
		return len(seen) < len(o.patterns)
	})
	return Result{Matched: len(seen) == len(o.patterns), Detail: "pm(match_all)"}, nil
}

// ---------------------------------------------------------------- 数值算子

type cmpOp struct {
	kind string
	v    float64
}

func (o cmpOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	n, ok := parseNumber(in)
	if !ok {
		return Result{}, nil
	}
	var matched bool
	switch o.kind {
	case "gt":
		matched = n > o.v
	case "ge":
		matched = n >= o.v
	case "lt":
		matched = n < o.v
	case "le":
		matched = n <= o.v
	}
	return Result{Matched: matched, Detail: o.kind}, nil
}

type withinOp struct{ lo, hi float64 }

func (o withinOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	n, ok := parseNumber(in)
	if !ok {
		return Result{}, nil
	}
	return Result{Matched: n >= o.lo && n <= o.hi, Detail: "within"}, nil
}

type byteRangeOp struct{ allowed [256]bool }

func (o byteRangeOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	for _, c := range in {
		if !o.allowed[c] {
			return Result{Matched: true, Detail: fmt.Sprintf("越界字节 0x%02x", c)}, nil
		}
	}
	return Result{}, nil
}

// ---------------------------------------------------------------- 网络算子

type ipMatchOp struct{ prefixes []netip.Prefix }

func (o ipMatchOp) Eval(_ *EvalCtx, in []byte) (Result, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(string(in)))
	if err != nil {
		return Result{}, nil
	}
	for _, p := range o.prefixes {
		if p.Contains(addr) {
			return Result{Matched: true, Detail: "ipMatch"}, nil
		}
	}
	return Result{}, nil
}

// ---------------------------------------------------------------- 逻辑组合

type allOfOp struct{ ops []Compiled }

func (o allOfOp) Eval(ctx *EvalCtx, in []byte) (Result, error) {
	for _, sub := range o.ops {
		r, err := sub.Eval(ctx, in)
		if err != nil {
			return Result{}, err
		}
		if !r.Matched {
			return Result{}, nil
		}
	}
	return Result{Matched: true, Detail: "allOf"}, nil
}

type anyOfOp struct{ ops []Compiled }

func (o anyOfOp) Eval(ctx *EvalCtx, in []byte) (Result, error) {
	for _, sub := range o.ops {
		r, err := sub.Eval(ctx, in)
		if err != nil {
			return Result{}, err
		}
		if r.Matched {
			return Result{Matched: true, Detail: "anyOf"}, nil
		}
	}
	return Result{}, nil
}

type notOp struct{ op Compiled }

func (o notOp) Eval(ctx *EvalCtx, in []byte) (Result, error) {
	r, err := o.op.Eval(ctx, in)
	if err != nil {
		return Result{}, err
	}
	return Result{Matched: !r.Matched, Detail: "not"}, nil
}

type unconditionalOp struct{}

func (unconditionalOp) Eval(_ *EvalCtx, _ []byte) (Result, error) {
	return Result{Matched: true, Detail: "unconditionalMatch"}, nil
}

// ---------------------------------------------------------------- 工具

func bytesContains(hay, needle []byte) bool {
	return len(needle) > 0 && strings.Contains(string(hay), string(needle))
}

func bytesHasPrefix(hay, prefix []byte) bool {
	return len(hay) >= len(prefix) && string(hay[:len(prefix)]) == string(prefix)
}

func bytesHasSuffix(hay, suffix []byte) bool {
	return len(hay) >= len(suffix) && string(hay[len(hay)-len(suffix):]) == string(suffix)
}

func parseNumber(in []byte) (float64, bool) {
	s := strings.TrimSpace(string(in))
	if s == "" {
		return 0, false
	}
	var f float64
	if _, err := fmt.Sscanf(s, "%g", &f); err != nil {
		return 0, false
	}
	return f, true
}

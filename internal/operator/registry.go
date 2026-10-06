package operator

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"donothack/internal/ac"
	"donothack/internal/kv"
)

// 本文件把算子实现注册进注册表，并在这里做**参数校验**。
//
// 校验放在加载期而不是运行期：规则写错了要立刻整批拒绝，
// 而不是等真实流量打上来才发现某条规则永远不会命中。
func init() {
	registerStringOps()
	registerNumericOps()
	registerNetworkOps()
	registerLogicalOps()
	registerSemanticOps()
}

func registerStringOps() {
	Register("eq", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		v, ok := p.Get("value")
		if !ok {
			return nil, errors.New("缺少 value 参数")
		}
		return eqOp{v: []byte(fmt.Sprint(v))}, nil
	})
	// equals 是 eq 的别名（照顾 SecRules 用户的习惯）
	Register("equals", func(cc *CompileCtx, p kv.Params) (Compiled, error) {
		return compileWith("eq", p, cc)
	})

	Register("eqIgnoreCase", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		v, ok := p.Get("value")
		if !ok {
			return nil, errors.New("缺少 value 参数")
		}
		return eqIgnoreCaseOp{v: fmt.Sprint(v)}, nil
	})

	Register("contains", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		v, ok := p.Get("value")
		if !ok {
			return nil, errors.New("缺少 value 参数")
		}
		s := fmt.Sprint(v)
		if s == "" {
			return nil, errors.New("value 不能为空（空串会命中所有请求）")
		}
		return containsOp{v: []byte(s)}, nil
	})

	Register("containsAny", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		vs := p.Strings("values")
		if len(vs) == 0 {
			return nil, errors.New("缺少 values 参数")
		}
		out := make([][]byte, 0, len(vs))
		for _, v := range vs {
			if v == "" {
				return nil, errors.New("values 里不能有空串")
			}
			out = append(out, []byte(v))
		}
		return containsAnyOp{vs: out}, nil
	})

	Register("startsWith", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		v := p.String("value")
		if v == "" {
			return nil, errors.New("缺少 value 参数")
		}
		return prefixOp{v: []byte(v)}, nil
	})
	Register("endsWith", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		v := p.String("value")
		if v == "" {
			return nil, errors.New("缺少 value 参数")
		}
		return prefixOp{v: []byte(v), suffix: true}, nil
	})

	Register("regex", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		pattern := p.String("pattern")
		if pattern == "" {
			return nil, errors.New("缺少 pattern 参数")
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("正则无法编译（只支持 RE2 语法，不支持反向引用/环视）：%w", err)
		}
		return regexOp{re: re, capture: p.Bool("capture"), pattern: pattern}, nil
	})

	Register("regexCaseInsensitive", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		pattern := p.String("pattern")
		if pattern == "" {
			return nil, errors.New("缺少 pattern 参数")
		}
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			return nil, fmt.Errorf("正则无法编译（只支持 RE2 语法）：%w", err)
		}
		return regexOp{re: re, capture: p.Bool("capture"), pattern: pattern}, nil
	})

	Register("pm", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		pats := p.Strings("patterns")
		if len(pats) == 0 {
			return nil, errors.New("缺少 patterns 参数")
		}
		return buildPM(pats, p.Bool("match_all"))
	})

	Register("pmFromFile", func(cc *CompileCtx, p kv.Params) (Compiled, error) {
		name := p.String("file")
		if name == "" {
			return nil, errors.New("缺少 file 参数")
		}
		lines, err := loadLines(cc.FileBase, name)
		if err != nil {
			return nil, err
		}
		pats := make([]string, 0, len(lines))
		for _, l := range lines {
			pats = append(pats, string(l))
		}
		return buildPM(pats, p.Bool("match_all"))
	})
}

func buildPM(pats []string, matchAll bool) (Compiled, error) {
	acPats := make([]ac.Pattern, 0, len(pats))
	for i, s := range pats {
		if s == "" {
			return nil, errors.New("patterns 里不能有空串（空串会命中所有请求）")
		}
		acPats = append(acPats, ac.Pattern{Literal: []byte(s), ID: int32(i)})
	}
	return pmOp{m: ac.New(acPats), matchAll: matchAll, patterns: pats}, nil
}

func registerNumericOps() {
	for _, kind := range []string{"gt", "ge", "lt", "le"} {
		k := kind
		Register(k, func(_ *CompileCtx, p kv.Params) (Compiled, error) {
			v, ok := p.Float("value")
			if !ok {
				return nil, errors.New("缺少 value 参数（数值）")
			}
			return cmpOp{kind: k, v: v}, nil
		})
	}

	Register("within", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		lo, ok1 := p.Float("min")
		hi, ok2 := p.Float("max")
		if !ok1 || !ok2 {
			return nil, errors.New("缺少 min / max 参数")
		}
		if lo > hi {
			return nil, fmt.Errorf("min(%v) 大于 max(%v)", lo, hi)
		}
		return withinOp{lo: lo, hi: hi}, nil
	})

	Register("validateByteRange", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		spec := p.String("range")
		if spec == "" {
			return nil, errors.New("缺少 range 参数（如 \"1-255\" 或 \"9,10,13,32-126\"）")
		}
		var allowed [256]bool
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if i := strings.IndexByte(part, '-'); i > 0 {
				lo, err1 := parseByte(part[:i])
				hi, err2 := parseByte(part[i+1:])
				if err1 != nil || err2 != nil {
					return nil, fmt.Errorf("无法解析字节范围 %q", part)
				}
				if lo > hi {
					return nil, fmt.Errorf("字节范围 %q 的上下界颠倒了", part)
				}
				for b := lo; b <= hi; b++ {
					allowed[b] = true
				}
				continue
			}
			b, err := parseByte(part)
			if err != nil {
				return nil, fmt.Errorf("无法解析字节 %q", part)
			}
			allowed[b] = true
		}
		return byteRangeOp{allowed: allowed}, nil
	})
}

func parseByte(s string) (int, error) {
	s = strings.TrimSpace(s)
	var n int64
	var err error
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		n, err = strconv.ParseInt(s[2:], 16, 16)
	} else {
		n, err = strconv.ParseInt(s, 10, 16)
	}
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 255 {
		return 0, fmt.Errorf("字节值越界：%d", n)
	}
	return int(n), nil
}

func registerNetworkOps() {
	Register("ipMatch", func(_ *CompileCtx, p kv.Params) (Compiled, error) {
		items := p.Strings("cidrs")
		if len(items) == 0 {
			return nil, errors.New("缺少 cidrs 参数")
		}
		return buildIPMatch(items)
	})
	Register("ipMatchFromFile", func(cc *CompileCtx, p kv.Params) (Compiled, error) {
		name := p.String("file")
		if name == "" {
			return nil, errors.New("缺少 file 参数")
		}
		lines, err := loadLines(cc.FileBase, name)
		if err != nil {
			return nil, err
		}
		items := make([]string, 0, len(lines))
		for _, l := range lines {
			items = append(items, string(l))
		}
		return buildIPMatch(items)
	})
}

func buildIPMatch(items []string) (Compiled, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(s); err == nil {
			out = append(out, pfx.Masked())
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q 既不是 CIDR 也不是 IP", s)
		}
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	if len(out) == 0 {
		return nil, errors.New("cidrs 里没有有效条目")
	}
	return ipMatchOp{prefixes: out}, nil
}

func registerLogicalOps() {
	Register("allOf", func(cc *CompileCtx, p kv.Params) (Compiled, error) { return buildCombine(cc, p, true) })
	Register("anyOf", func(cc *CompileCtx, p kv.Params) (Compiled, error) { return buildCombine(cc, p, false) })

	Register("not", func(cc *CompileCtx, p kv.Params) (Compiled, error) {
		spec, ok := p.Get("operator")
		if !ok {
			return nil, errors.New("缺少 operator 参数")
		}
		sub, err := compileSpec(cc, spec)
		if err != nil {
			return nil, err
		}
		return notOp{op: sub}, nil
	})

	Register("unconditionalMatch", func(_ *CompileCtx, _ kv.Params) (Compiled, error) {
		return unconditionalOp{}, nil
	})
}

func buildCombine(cc *CompileCtx, p kv.Params, all bool) (Compiled, error) {
	specs, ok := p.Get("operators")
	if !ok {
		if single, ok2 := p.Get("operator"); ok2 {
			specs = []any{single}
		} else {
			return nil, errors.New("缺少 operators 参数")
		}
	}
	list, ok := specs.([]any)
	if !ok {
		return nil, errors.New("operators 必须是列表")
	}
	if len(list) == 0 {
		return nil, errors.New("operators 不能为空")
	}
	next := &CompileCtx{Depth: cc.Depth + 1, FileBase: cc.FileBase}
	subs := make([]Compiled, 0, len(list))
	for _, s := range list {
		sub, err := compileSpec(next, s)
		if err != nil {
			return nil, err
		}
		subs = append(subs, sub)
	}
	if all {
		return allOfOp{ops: subs}, nil
	}
	return anyOfOp{ops: subs}, nil
}

// compileSpec 编译一个嵌套的算子规格：{name: ..., params: {...}}
func compileSpec(cc *CompileCtx, spec any) (Compiled, error) {
	m, ok := spec.(map[string]any)
	if !ok {
		if s, isStr := spec.(string); isStr {
			return compileWith(s, nil, cc)
		}
		return nil, fmt.Errorf("算子规格必须是 {name, params} 形式，得到 %T", spec)
	}
	name, _ := m["name"].(string)
	if name == "" {
		return nil, errors.New("算子规格缺少 name")
	}
	var params kv.Params
	if pv, ok := m["params"]; ok && pv != nil {
		pm, ok := pv.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("算子 %s 的 params 必须是映射，得到 %T", name, pv)
		}
		params = kv.Params(pm)
	}
	return compileWith(name, params, cc)
}

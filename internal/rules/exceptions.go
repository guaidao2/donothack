package rules

import (
	"net/netip"
	"path"
	"strings"
	"time"
)

// ExceptionInput 是例外匹配需要的请求特征。
type ExceptionInput struct {
	Path   string // 规范化后的路径
	Method string
	IP     string
}

// MatchResult 是例外匹配结果。
type MatchResult struct {
	// Hit 命中的例外（可能为 nil）。
	Hit *Exception
	// SkipAll 表示这条例外要求整请求不过规则（mode: skip）。
	SkipAll bool
	// Disabled 是被禁用的规则 ID 集合；类目用 "category:<name>" 形式。
	Disabled map[string]bool
}

// MatchExceptions 找第一条命中的例外。
//
// 多条例外同时命中时取第一条（文件顺序），并且把它们的禁用项**合并** ——
// 例外是"放行"语义，多条命中时结论应当更宽，这样运维不会被
// "两条例外互相覆盖"这种问题坑到。
func (rs *RuleSet) MatchExceptions(in ExceptionInput) MatchResult {
	return MatchExceptionList(rs.exceptions, in)
}

// MatchExceptionList 在一组例外里找命中的那些（规则文件里的例外与控制台维护的
// 例外共用这套逻辑 —— 两套判断逻辑迟早会分叉，那种 bug 最难查）。
func MatchExceptionList(list []*Exception, in ExceptionInput) MatchResult {
	res := MatchResult{}
	if len(list) == 0 {
		return res
	}
	now := time.Now()
	for _, ex := range list {
		if !ex.Expires.IsZero() && now.After(ex.Expires) {
			// 过期例外自动失效：这是"临时例外不会变成永久后门"的机械保证。
			continue
		}
		if !exceptionMatches(ex, in) {
			continue
		}
		if res.Hit == nil {
			res.Hit = ex
		}
		if res.Disabled == nil {
			res.Disabled = map[string]bool{}
		}
		for _, id := range ex.DisableRules {
			res.Disabled[strings.ToUpper(strings.TrimSpace(id))] = true
			// 支持通配符：XSS-*
			if strings.HasSuffix(id, "*") {
				res.Disabled["prefix:"+strings.ToUpper(strings.TrimSuffix(id, "*"))] = true
			}
		}
		for _, c := range ex.DisableCategory {
			res.Disabled["category:"+strings.ToLower(strings.TrimSpace(c))] = true
		}
		if ex.Mode == "skip" {
			res.SkipAll = true
		}
	}
	return res
}

// IsRuleDisabled 判断某条规则是否被例外禁用。
func (res MatchResult) IsRuleDisabled(ruleID, category string) bool {
	if len(res.Disabled) == 0 {
		return false
	}
	if res.Disabled[strings.ToUpper(ruleID)] {
		return true
	}
	if res.Disabled["category:"+category] {
		return true
	}
	// 前缀通配
	for k := range res.Disabled {
		if strings.HasPrefix(k, "prefix:") && strings.HasPrefix(strings.ToUpper(ruleID), strings.TrimPrefix(k, "prefix:")) {
			return true
		}
	}
	return false
}

func exceptionMatches(ex *Exception, in ExceptionInput) bool {
	// 所有写了条件的维度都必须满足（AND 语义）。
	if len(ex.Paths) > 0 && !anyGlob(ex.Paths, in.Path) {
		return false
	}
	if len(ex.Methods) > 0 && !anyEqualFold(ex.Methods, in.Method) {
		return false
	}
	if len(ex.SourceIPs) > 0 && !anyIPMatch(ex.SourceIPs, in.IP) {
		return false
	}
	// 条件全空的例外是"匹配一切"，那等于全站放行 —— 加载期已要求写清 reason，
	// 这里再兜一层：条件全空时不生效。
	if len(ex.Paths) == 0 && len(ex.Methods) == 0 && len(ex.SourceIPs) == 0 {
		return false
	}
	return true
}

func anyGlob(patterns []string, s string) bool {
	for _, p := range patterns {
		if globMatch(p, s) {
			return true
		}
	}
	return false
}

// globMatch 支持 "*" 通配与尾部 "/**" 前缀匹配。
func globMatch(pattern, s string) bool {
	if strings.HasSuffix(pattern, "**") {
		return strings.HasPrefix(s, strings.TrimSuffix(pattern, "**"))
	}
	ok, err := path.Match(pattern, s)
	if err == nil && ok {
		return true
	}
	// "/admin/api/*" 这种要能匹配 "/admin/api/v1/x"（path.Match 的 * 不跨 /）
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(s, strings.TrimSuffix(pattern, "*"))
	}
	return false
}

func anyEqualFold(list []string, s string) bool {
	for _, item := range list {
		if equalFold(strings.TrimSpace(item), s) {
			return true
		}
	}
	return false
}

func anyIPMatch(list []string, ip string) bool {
	if ip == "" {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, item := range list {
		item = strings.TrimSpace(item)
		if pfx, err := netip.ParsePrefix(item); err == nil {
			if pfx.Contains(addr) {
				return true
			}
			continue
		}
		if a, err := netip.ParseAddr(item); err == nil && a == addr {
			return true
		}
	}
	return false
}

// NewException 构造一条例外（控制台用）。
//
// 校验与 YAML 加载路径**完全一致**：reason 与 expires 必填、expires 不超过一年、
// mode 只能是 skip / detect_only。让控制台绕开这些约束等于把"例外必须写清原因、
// 必须有过期时间"这条纪律作废 —— 半年后没人敢删的永久后门都是这么来的。
func NewException(id, reason string, expires time.Time, paths, methods, sourceIPs,
	disableRules, disableCategories []string, skipRateLimit bool, mode string) (*Exception, error) {

	ref := SourceRef{File: "console", Index: 0}
	ye := yamlException{
		ID:              id,
		Reason:          reason,
		Expires:         yamlDate{t: expires},
		Match:           yamlExceptionMatch{Paths: paths, Methods: methods, SourceIPs: sourceIPs},
		DisableRules:    disableRules,
		DisableCategory: disableCategories,
		SkipRateLimit:   skipRateLimit,
		Mode:            mode,
	}
	return compileException(ye, ref)
}

// MatchInput 供引擎判断一条请求是否命中例外。
// （与 ExceptionInput 等价，保留旧名以免改动调用方。）
type MatchInput = ExceptionInput

// Merge 合并另一份匹配结果（文件例外 + 控制台例外的结论要并起来）。
func (res *MatchResult) Merge(other MatchResult) {
	if other.Hit != nil && res.Hit == nil {
		res.Hit = other.Hit
	}
	if other.SkipAll {
		res.SkipAll = true
	}
	for k := range other.Disabled {
		if res.Disabled == nil {
			res.Disabled = map[string]bool{}
		}
		res.Disabled[k] = true
	}
}

// Package rules 负责规则集的加载、校验、编译与索引。
//
// 三条原则（docs/RULES.md、docs/DESIGN.md §9）：
//  1. **未知名字一律整批拒绝**：变换名、算子名、变量集合写错就报错停止，
//     绝不做"部分加载"。部分加载会制造"以为有 500 条规则其实只加载了 300 条"
//     这种最难查的缺口。
//  2. **编译期把活干完**：正则预编译、Aho-Corasick 预构建、变换链归一化去重、
//     目标展开计划全部在加载时算好，运行期只做匹配。
//  3. **编译产物不可变**：RuleSet 构建后只读，由 atomic.Pointer 原子替换，
//     在途请求不会看到半成品规则集。
package rules

import (
	"fmt"
	"regexp"
	"time"

	"donothack/internal/kv"
	"donothack/internal/operator"
	"donothack/internal/tx"
)

// SourceRef 记录规则来自哪个文件的第几行，用于报错定位。
type SourceRef struct {
	File  string
	Line  int
	Index int // 文件内第几条
}

func (s SourceRef) String() string {
	if s.Line > 0 {
		return fmt.Sprintf("%s:%d", s.File, s.Line)
	}
	return s.File
}

// TestCase 是规则自带的正负样本。加载期会跑一遍：
// 正样本必须命中、负样本必须不命中，否则拒绝加载整批规则。
type TestCase struct {
	Positive []string
	Negative []string
}

// VarPlan 是编译好的目标展开计划。
type VarPlan struct {
	Collection string
	Selector   string
	SelectorRe *regexp.Regexp
	Exclude    []string
	Count      bool
}

// CompiledRule 是可直接执行的规则。
//
// **构建后不可变**，被所有请求共享，因此所有字段都必须只读。
type CompiledRule struct {
	ID       string
	Message  string
	Phase    tx.Phase
	Severity tx.Severity
	Category string
	Score    int
	Tags     []string

	HardBlock bool // 命中即终止本阶段并立即拦截
	Chain     bool // 链式规则：上一条命中才评估下一条
	Enabled   bool

	Targets        []VarPlan
	Transforms     []TransformFn
	TransformNames []string
	ChainID        int // 归一化后的变换链编号（用于去重）
	Op             operator.Compiled
	OperatorName   string

	// 预筛用
	Literals      [][]byte
	Prefilterable bool // false 表示该规则必须每请求都评估（如纯 entropy）

	Source SourceRef
	Test   TestCase

	// rawParams 是算子原始参数，编译后仍保留：提取预筛字面量、控制台展示、
	// 以及将来做规则影响预演时都要用。
	rawParams kv.Params
}

// TransformFn 是变换函数签名（与 transform.Func 一致，这里复述以避免
// rules 包对 transform 包产生不必要的耦合面）。
type TransformFn = func(in []byte, params kv.Params) ([]byte, error)

// RuleSet 是编译后的规则全集。不可变。
type RuleSet struct {
	Version  string // 内容哈希，进审计
	LoadedAt time.Time
	Source   string // 加载来源（目录/文件列表）

	phases [6]*phaseIndex
	byID   map[string]*CompiledRule
	// allRules 是全部规则（含被禁用的），下标稳定。
	allRules []*CompiledRule

	chains     []ChainInfo
	exceptions []*Exception
	localities Stats
}

// ChainInfo 是一条归一化后的变换链。
type ChainInfo struct {
	Names string // 用于日志与报错
	Fns   []TransformFn
	Rules int // 有多少条规则在用
}

// Stats 是加载期统计，启动时打印出来，便于发现规则集问题。
type Stats struct {
	Files          int
	Rules          int
	Enabled        int
	Disabled       int
	Chains         int
	LiteralRules   int // 有字面量、可进预筛的规则数
	NoLiteralRules int // 无字面量、必须每请求评估的规则数
	ShortLiterals  int // 字面量短于 3 字节被排除在预筛外的数量
	PrefilterNodes int
	ByCategory     map[string]int
	ByPhase        map[int]int
	Warnings       []string
}

// Errors 是加载期的错误集合，按文件与行号组织。
type Errors struct {
	List []error
}

func (e *Errors) add(format string, args ...any) {
	e.List = append(e.List, fmt.Errorf(format, args...))
}

func (e *Errors) Err() error {
	switch len(e.List) {
	case 0:
		return nil
	case 1:
		return e.List[0]
	}
	msg := fmt.Sprintf("共 %d 个问题：", len(e.List))
	for i, err := range e.List {
		if i >= 12 {
			msg += fmt.Sprintf("\n  … 还有 %d 条", len(e.List)-i)
			break
		}
		msg += "\n  - " + err.Error()
	}
	return fmt.Errorf("%s", msg)
}

// Exception 是例外规则（白名单）。
//
// 硬性要求：reason 与 expires 必填 —— 防止"临时例外"变成永久后门。
type Exception struct {
	ID              string
	Reason          string
	Expires         time.Time
	Paths           []string
	Methods         []string
	SourceIPs       []string
	DisableRules    []string
	DisableCategory []string
	SkipRateLimit   bool
	Mode            string
	Source          SourceRef

	pathRes []*regexp.Regexp
}

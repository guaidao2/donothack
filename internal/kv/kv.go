// Package kv 提供一个极小的、规则参数用的键值类型。
//
// 存在的理由：transform 与 operator 两个包都需要读规则里写的参数
// （`params: {pattern: "..."}`），但它们在依赖图上是兄弟关系，
// 互不依赖，也不该依赖 rules 包。所以把共享的容器类型放在这里。
package kv

import (
	"fmt"
	"strconv"
	"strings"
)

// Params 是规则参数的通用容器。
type Params map[string]any

// Get 取值。
func (p Params) Get(key string) (any, bool) {
	if p == nil {
		return nil, false
	}
	v, ok := p[key]
	return v, ok
}

// String 取字符串参数。
func (p Params) String(key string) string {
	v, ok := p.Get(key)
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(v)
	}
}

// Int 取整数参数（YAML 解析出来的整数可能是 int / int64 / float64）。
func (p Params) Int(key string) (int, bool) {
	v, ok := p.Get(key)
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case int:
		return t, true
	case int64:
		return int(t), true
	case float64:
		return int(t), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// Float 取浮点参数。
func (p Params) Float(key string) (float64, bool) {
	v, ok := p.Get(key)
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

// Bool 取布尔参数。
func (p Params) Bool(key string) bool {
	v, ok := p.Get(key)
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(t))
		return err == nil && b
	default:
		return false
	}
}

// Strings 取字符串列表参数。
func (p Params) Strings(key string) []string {
	v, ok := p.Get(key)
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case string:
		// 单个字符串也当作单元素列表，规则作者少写一层数组不算错。
		return []string{t}
	default:
		return nil
	}
}

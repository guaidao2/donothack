package rules

import (
	"strconv"

	"donothack/internal/tx"
)

// expandCollection 遍历一个集合里的全部值，fn 返回 false 时提前结束。
//
// key 是**审计里要显示的目标名**（含参数名，如 "username"）；
// 值可能为 nil（如只关心数量的集合）。
func expandCollection(v *tx.Collections, col string, fn func(key string, val []byte) bool) {
	switch col {
	case "ARGS":
		v.Args.ForEach(func(k, val []byte) bool { return fn(string(k), val) })
	case "ARGS_GET":
		v.ArgsGet.ForEach(func(k, val []byte) bool { return fn(string(k), val) })
	case "ARGS_POST":
		v.ArgsPost.ForEach(func(k, val []byte) bool { return fn(string(k), val) })
	case "ARGS_JSON":
		v.ArgsJSON.ForEach(func(k, val []byte) bool { return fn(string(k), val) })
	case "ARGS_XML":
		v.ArgsXML.ForEach(func(k, val []byte) bool { return fn(string(k), val) })
	case "ARGS_NAMES":
		v.Args.ForEach(func(k, _ []byte) bool { return fn(string(k), []byte(k)) })
	case "REQUEST_URI":
		fn("", []byte(v.URI))
	case "REQUEST_PATH":
		// **双形态**：原始路径与规范化路径都要过检测。
		// 攻击者专门利用"WAF 规范化方式与后端不一致"这个差异 ——
		// 只查一种形态，就等于给对方留了一半空间。
		if v.RawPath != "" {
			if !fn("(raw)", []byte(v.RawPath)) {
				return
			}
		}
		fn("", []byte(v.Path))
	case "REQUEST_METHOD":
		fn("", []byte(v.Method))
	case "REQUEST_PROTOCOL":
		fn("", []byte(v.Proto))
	case "REQUEST_HEADERS":
		v.Headers.ForEach(func(k, val []byte) bool { return fn(string(k), val) })
	case "REQUEST_HEADERS_NAMES":
		v.Headers.ForEach(func(k, _ []byte) bool { return fn(string(k), []byte(k)) })
	case "REQUEST_COOKIES":
		v.Cookies.ForEach(func(k, val []byte) bool { return fn(string(k), val) })
	case "REQUEST_COOKIES_NAMES":
		v.Cookies.ForEach(func(k, _ []byte) bool { return fn(string(k), []byte(k)) })
	case "REQUEST_BODY":
		if v.Body != nil {
			fn("", v.Body)
		}
	case "REMOTE_ADDR":
		fn("", []byte(v.RawIP))
	case "ARGS_COUNT":
		fn("", []byte(strconv.Itoa(v.Args.Len())))
	case "REQUEST_URI_LENGTH":
		fn("", []byte(strconv.Itoa(len(v.URI))))
	case "REQUEST_BODY_LENGTH":
		fn("", []byte(strconv.Itoa(len(v.Body))))
	case "FILES":
		for _, metas := range v.Files {
			for i := range metas {
				if !fn(metas[i].FieldName, []byte(metas[i].FileName)) {
					return
				}
			}
		}
	case "FILES_NAMES":
		for name := range v.Files {
			if !fn(name, []byte(name)) {
				return
			}
		}
	case "FILES_SIZES":
		for _, metas := range v.Files {
			for i := range metas {
				if !fn(metas[i].FieldName, []byte(strconv.FormatInt(metas[i].Size, 10))) {
					return
				}
			}
		}
	case "FILES_MAGIC":
		for _, metas := range v.Files {
			for i := range metas {
				m := metas[i]
				if m.MagicLen == 0 {
					continue
				}
				if !fn(m.FieldName, m.Magic[:m.MagicLen]) {
					return
				}
			}
		}
	}
}

// targetMatches 判断一个键是否落在 target 的 selector 范围内。
func targetMatches(plan VarPlan, key string) bool {
	if plan.Count {
		return true
	}
	for _, ex := range plan.Exclude {
		if equalFold(key, ex) {
			return false
		}
	}
	switch {
	case plan.Selector == "" && plan.SelectorRe == nil:
		return true
	case plan.SelectorRe != nil:
		return plan.SelectorRe.MatchString(key)
	default:
		return equalFold(key, plan.Selector)
	}
}

// equalFold 是不分配的大小写不敏感比较（参数名大小写各家实现不同，统一按不敏感处理）。
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// TargetLabel 生成审计用的目标名，如 ARGS:username。
func TargetLabel(col, key string) string {
	if key == "" {
		return col
	}
	return col + ":" + key
}

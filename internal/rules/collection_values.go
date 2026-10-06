package rules

import (
	"strconv"

	"donothack/internal/tx"
)

// collectionValues 把**标量集合**的值写进 out（最多两个：原始与规范化），
// 返回实际个数。参数类集合不走这里（用 paramsOf 直接按下标迭代）。
//
// 为什么不返回切片：返回 `[][]byte` 会让每个请求多分配一次切片头。
// 热路径上"零分配"是硬门禁，所以调用方给一块固定的数组。
//
// key 与值的对应关系（审计里要显示目标名）：
//   - REQUEST_PATH 会给出两个值：`(raw)` 与规范化后的路径；
//   - 其余标量集合只有一个值，key 为空串。
func collectionValues(v *tx.Collections, col string, out *[2][]byte) int {
	switch col {
	case "REQUEST_URI":
		out[0] = []byte(v.URI)
		return 1
	case "REQUEST_PATH":
		// **双形态**：原始路径与规范化路径都要过检测。
		// 攻击者专门利用"WAF 规范化方式与后端不一致"这个差异 ——
		// 只查一种形态，就等于给对方留了一半空间。
		n := 0
		if v.RawPath != "" {
			out[n] = []byte(v.RawPath)
			n++
		}
		out[n] = []byte(v.Path)
		n++
		return n
	case "REQUEST_METHOD":
		out[0] = []byte(v.Method)
		return 1
	case "REQUEST_PROTOCOL":
		out[0] = []byte(v.Proto)
		return 1
	case "REQUEST_BODY":
		if v.Body == nil {
			return 0
		}
		out[0] = v.Body
		return 1
	case "REMOTE_ADDR":
		out[0] = []byte(v.RawIP)
		return 1
	case "ARGS_COUNT":
		out[0] = []byte(strconv.Itoa(v.Args.Len()))
		return 1
	case "REQUEST_URI_LENGTH":
		out[0] = []byte(strconv.Itoa(len(v.URI)))
		return 1
	case "REQUEST_BODY_LENGTH":
		out[0] = []byte(strconv.Itoa(len(v.Body)))
		return 1
	case "FILES":
		// 文件字段名与文件名：文件名是攻击面（路径穿越、双扩展名）。
		n := 0
		for _, metas := range v.Files {
			for i := range metas {
				if n < len(out) {
					out[n] = []byte(metas[i].FileName)
					n++
				}
			}
			if n >= len(out) {
				break
			}
		}
		return n
	case "FILES_NAMES":
		n := 0
		for name := range v.Files {
			if n < len(out) {
				out[n] = []byte(name)
				n++
			}
		}
		return n
	case "FILES_SIZES":
		n := 0
		for _, metas := range v.Files {
			for i := range metas {
				if n < len(out) {
					out[n] = []byte(strconv.FormatInt(metas[i].Size, 10))
					n++
				}
			}
		}
		return n
	case "FILES_MAGIC":
		n := 0
		for _, metas := range v.Files {
			for i := range metas {
				m := metas[i]
				if m.MagicLen == 0 {
					continue
				}
				if n < len(out) {
					out[n] = m.Magic[:m.MagicLen]
					n++
				}
			}
		}
		return n
	}
	return 0
}

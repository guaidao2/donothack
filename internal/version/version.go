// Package version 保存构建期注入的版本信息。
//
// 通过 -ldflags 注入：
//
//	-X donothack/internal/version.Version=...
//	-X donothack/internal/version.Commit=...
//	-X donothack/internal/version.Date=...
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version 语义化版本或 git describe 结果。
	Version = "dev"
	// Commit 构建时的提交号。
	Commit = "none"
	// Date 构建时间（RFC3339）。
	Date = "unknown"
)

// Authors 是项目作者。
//
// 放在这里而不是只写进 README：`donothack version` 的输出是**随二进制走的**，
// 二进制被拷到哪儿署名就跟到哪儿 —— 只写在文档里，发布出去的包就没有作者了。
const Authors = "guaidao2 & coolmoon"

// Info 返回一行可打印的版本摘要。
func Info() string {
	return fmt.Sprintf("donothack %s (commit %s, built %s, %s/%s, %s)",
		Version, Commit, Date, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// Full 返回带作者的完整版本信息（供 `donothack version` 打印）。
func Full() string {
	return Info() + "\n作者：" + Authors
}

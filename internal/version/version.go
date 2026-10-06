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

// Info 返回一行可打印的版本摘要。
func Info() string {
	return fmt.Sprintf("donothack %s (commit %s, built %s, %s/%s, %s)",
		Version, Commit, Date, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

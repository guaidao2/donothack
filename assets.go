// Package donothack 只做一件事：把前端静态资源嵌进二进制。
//
// 为什么放在模块根目录：`go:embed` 不能引用包目录之外的路径，
// 而 `web/` 按文档就应当在仓库根（谁都能一眼看到前端在哪）。
// 所以这里放一个只含 embed 声明的包，供 internal/console 消费。
package donothack

import "embed"

// WebFS 是前端静态资源（原生 ES module SPA，无构建链）。
//
// 用 `all:` 前缀：连 `_` 与 `.` 开头的文件也一起嵌入，
// 否则将来加个 `.well-known` 之类的文件会莫名其妙丢失。
//
//go:embed all:web
var WebFS embed.FS

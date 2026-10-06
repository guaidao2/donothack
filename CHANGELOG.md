# 更新日志

版本号遵循语义化版本。每个版本都打了 tag，可检出对照。

## v1.0.0 — 2026-10-06

首个正式版本。

**检测**

- 出厂 60 条规则 / 9 个文件，覆盖 SQL 注入、XSS、命令注入、路径穿越、文件包含、
  Webshell 上传、扫描器指纹、协议违规，按类目给分
- 反绕过解析：query / form / JSON / XML / multipart / cookie / header 统一拆平成
  扁平命名空间；路径规范化、HPP、值级编码文档（JSON、base64(JSON)）逐字段展开后再匹配
- 三种模式：`detect` 只记录、`block` 达阈值拦截、`mixed` 按类目分别设阈值
- 评分制裁决；弱信号（UA 指纹、单独引号、裸算术表达式）只记分，不单独触发拦截

**防护动作**

- 拦截页按 `Accept` 自适应 HTML / JSON / 纯文本，内容与品牌可在控制台修改
- 限速与临时封禁（429 + `Retry-After`）、Drop、Tarpit

**控制台**

- 总览与降级状态、事件检索与导出（JSONL / CSV）、规则启停与测试台、例外、IP 名单、
  限速、配置差异与热重载、告警通道、备份、操作审计、TOTP 两步验证
- 两层准入：HTTP Basic 门槛挡扫描器（未过门槛时所有路径统一 401），表单登录 + 会话做认证；
  写操作叠加 CSRF token、自定义头与 Origin 校验
- 前端原生 ES module，`go:embed` 进二进制，无 Node 构建链；payload 以纯文本节点展示

**运维**

- 配置热改：引擎模式与阈值、限速、拦截页、规则集可运行期原子替换；无效改动整批拒绝并回滚
- 过载降级 L0–L4；`block` 模式只允许 L1，再往上返回 503 而不是静默降检测
- 日志三道上限（单文件 / 保留份数 / 目录总配额）+ 磁盘水位优先丢日志
- webhook 告警：冷却合并、有界队列、默认禁止指向内网地址
- `/healthz`、`/readyz`（含降级与日志状态）、访问日志、类目统计

**性能**

- 热路径零分配作为构建门禁：`BenchmarkEngine_NoMatch` 0 allocs/op
- 变换链去重 + 共享 Aho-Corasick 预筛；响应零缓冲
- profile 分级：`small`（1 vCPU / 512 MiB）、`medium`（2 vCPU / 2 GiB）、`large`

**已知边界**

- 只做请求侧检测，不检查响应体
- 请求侧信息不足的形态（例如应用把参数当表达式求值）只记分不拦，避免误伤正常参数

## 更早的里程碑

开发期的里程碑 tag 都保留着，检出即可对照当时的状态：

`v0.0.1-design`、`v0.1.0-mvp`、`v0.2.0-parser`、`v0.3.0-engine`、`v0.4.0-protect`、
`v0.5.0-console-api`、`v0.6.0-acceptance-1`、`v0.7.0-console-wired`、`v0.8.0-perf-gate`、
`v0.9.0-ops-complete`、`v1.0.0-rc1` … `v1.0.0-rc4`

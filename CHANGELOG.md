# 变更日志

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

每个里程碑记录三件事：改了什么、怎么验证的、怎么回滚。

---

## [未发布]

### 新增

- 仓库初始化，确定 Git 工作流（`main` 全绿门禁、`feat/*` 分支、里程碑 tag、规则集独立提交）。
- `docs/DESIGN.md`：架构设计稿。包含总体架构与数据流、运行模式、核心抽象（Transaction / Collections / 变量寻址）、模块划分与依赖方向、关键 Go 接口、解析层防绕过设计、规则引擎编译与预筛方案、评分制决策模型、限速与封禁、响应侧检测、配置与热加载、可观测性、性能设计、安全与健壮性、测试策略与分阶段验收标准、Git 工作流、未决问题。
- `docs/RULES.md`：规则 DSL 规格。包含文件组织、规则字段、变量集合与选择器、变换清单、算子清单、例外与白名单机制、规则编写硬约束与反例、加载期校验与离线测试 CLI、SecRules 兼容层范围界定。
- `README.md`、`.gitignore`、`go.mod`。
- `docs/PERFORMANCE.md`（新增，**硬约束文档**）：以「1 vCPU / 512 MiB 的 VPS 也要能跑」为首要约束，给出 `small`/`medium`/`large` profile 分级与逐项数值、每请求 CPU 与内存预算表、热路径零分配硬指标与实现手段、变换链去重 + 共享 Aho-Corasick 预筛算法、GC 与内存控制（`GOMEMLIMIT` + `GOGC` 配合）、连接与超时上限、构建与部署参数（`GOAMD64=v1`、systemd `MemoryMax`/`OOMScoreAdjust`、镜像）、L1–L4 有界降级策略、低配明确取舍清单、性能验证方法（微基准 + 端到端 + 受限环境模拟 + pprof）。

### 变更

- 设计按「低配 VPS」约束回灌修订：
  - §1 目标加入「**低配 VPS 能跑**」并列为**首要约束**（1 vCPU / 512 MiB 为最低支持线）。
  - §9.1 编译期优化由「字面量预筛 + 规则内变换合并」升级为「**变换链全局去重 + 共享自动机 + 廉价算子组**」。
  - §13 配置结构加入 `profile`（`small`/`medium`/`large`/`auto`，按 cgroup 探测）。
  - §15 性能设计整章重写：分级 profile、零分配、逐项有界、有界降级，细节挂接 `docs/PERFORMANCE.md`。
  - §16 风险表加入「内存耗尽（慢速攻击 / 海量连接）」与「低配 VPS 上 CPU 被 WAF 吃穿」。
  - §17 各阶段验收门加入性能项，并新增 §17.5 性能门禁表（0 allocs/op、P99、RSS 等硬指标）。
  - §18 P0 提前纳入 profile 探测、内存上限、连接上限与压测脚本骨架；P2 纳入去重与预筛；P3 纳入降级与容量上限；P5 纳入真机基线。
  - 附录 B 配置示例改为 `small` 档实值（检查上限、连接上限、`MaxHeaderBytes`、超时、降级开关）。
  - README 同步：首要约束、目标性能改为 `small` profile 目标值、构建参数。

### 状态

设计与文档阶段，尚无实现代码。下一步 P0（骨架，含 profile 探测与性能地基）。

---

## 回滚参考

| 想回到 | 命令 |
| --- | --- |
| 设计稿状态 | `git checkout v0.0.1-design` |
| 查看设计与实现的差异 | `git diff v0.0.1-design..v0.1.0-mvp` |
| 撤销某次错误提交 | `git revert <sha>` |

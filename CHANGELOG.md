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
  - §1 目标加入「**低配 VPS 能跑**」并列为**首要约束**。
  - §9.1 编译期优化由「字面量预筛 + 规则内变换合并」升级为「**变换链全局去重 + 共享自动机 + 廉价算子组**」。
  - §13 配置结构加入 `profile`（`small`/`medium`/`large`/`auto`，按 cgroup 探测）。
  - §15 性能设计整章重写：分级 profile、零分配、逐项有界、有界降级，细节挂接 `docs/PERFORMANCE.md`。
  - §16 风险表加入「内存耗尽（慢速攻击 / 海量连接）」与「低配 VPS 上 CPU 被 WAF 吃穿」。
  - §17 各阶段验收门加入性能项，并新增 §17.5 性能门禁表（0 allocs/op、P99、RSS 等硬指标）。
  - §18 P0 提前纳入 profile 探测、内存上限、连接上限与压测脚本骨架；P2 纳入去重与预筛；P3 纳入降级与容量上限；P5 纳入真机基线。
  - README 同步：首要约束、目标性能、构建参数。

### 变更（第二稿：命名定稿 · 范围收窄 · 目标档调整）

- **命名定稿**：产品与二进制都叫 **donothack**（原 `wafd`），Go 模块路径 `donothack`。全仓库文档与 `go.mod` 同步替换。
- **检测范围收窄**：只做请求侧（请求头、请求体、参数），**不做响应侧检测**。
  - `DESIGN.md` §3 数据流与架构图改为响应零缓冲、流式透传；§1 目标表加入「检测准」为核心 KPI，非目标加入「不做响应侧检测」。
  - §5.2 响应字段与 §7.4 `Engine.Phase3/Phase4` 标记为保留未实现；§8.4 去掉响应体检查上限，改为上游失败不静默直连。
  - §12 整章改为「本轮不做，保留设计」，并写清将来恢复的代价（必须重算性能预算）。
  - `RULES.md` 的 `RESPONSE_*` 集合标记未实现；**写针对这些集合的规则在加载期直接报错**，不允许存在永远不生效的规则。
  - 收益：响应不进内存、无需 body tee，省掉整块响应缓冲的内存与延迟。
- **目标机型调整**：2 vCPU / 2 GiB（`medium`）为**目标档**，1 vCPU / 512 MiB（`small`）为**保底线**（初稿以 small 为主目标）。
  - `PERFORMANCE.md` §1 profile 表、§2 目标值、§2.3 内存预算、§6 连接参数、§7.2 systemd、§7.3 Docker 全部按 medium 与 small 双档给出。
  - `DESIGN.md` §15.1/§15.3、§17.3、§17.5、§18、附录 B 同步；配置示例改为 `medium` 档实值。
- **降级阶梯重定义**：去掉已不存在的「关阶段 4」，改为 L1 丢日志 / L2 降检测深度（跳过昂贵算子）/ L3 只跑阶段 1 / L4 旁路。**`block` 模式只允许 L1**，L2 及以上拒绝降级并返回 503。
- TLS 默认关（站点可能就跑明文 HTTP）；明文站下 `real_ip.trusted_proxies` 必须配准，否则限速与封禁形同虚设 —— 已在 `DESIGN.md` §13.1 与 §3 单独写明。
- 附录 C 待确认清单区分「已定」与「仍待确认」。

### 新增（第三稿：Web 控制台）

- **新增 `docs/CONSOLE.md`**：Web 控制台设计。原「不做 GUI，管理走 API + 命令行」的判断作废。
  - 硬约束：控制面与数据面分离 —— 数据面只读不可变快照；所有写操作只能走 `control.Apply`（解析 → 校验 → 内置语料自测 → 原子替换 → 失败回滚并回显错误）；单写者串行；提供 `Preview` 做改动影响预演；控制台独立端口、独立 mux、独立限流。
  - 控制台开销上限：查询最大 24h、只扫最近 3 天文件、单页 ≤ 200 行、服务端超时 3s，**禁止全量扫描**；额外内存 `medium` ≤ 24 MiB / `small` ≤ 8 MiB；控制台流量不进检测引擎，避免规则把管理员操作拦掉。
  - 八个页面：概览、攻击事件（含 SSE 实时）、规则管理、规则测试台、例外与白名单、CC 防护/限速、系统设置、操作审计。
  - 前端：**原生 ES module SPA，无 Node 构建链**；无 TypeScript/JSX/框架；图表用 vendored uPlot；资源 `go:embed` + 内容版本做缓存失效；CSP 无 `unsafe-inline`。
  - 认证与安全：`basic`（+ 强制自定义头 + Origin 校验）/`session`/`both`；标准库 PBKDF2-HMAC-SHA256 600k 迭代（避开 `x/crypto` 依赖）；TOTP 自行实现；单 IP 5 次失败锁 15 分钟 + 全局限流；公网明文绑定需显式 `allow_insecure` 才启动。
  - **绝不回显攻击 payload 原文**（防控制台自种存储型 XSS），只显示摘要；查看原文需单独动作并记操作审计。
  - 事件存储分层：内存 ring buffer + 1440 个分钟聚合桶 + 按天 JSONL 与偏移索引；可选纯 Go SQLite 默认关；**不引外部数据库**。
  - API：`/api/v1/*`，CLI `donothackctl` 与控制台共用同一套。

### 变更（第三稿）

- `DESIGN.md`：§1 目标表加入「可运维」；§6 模块表加入 `internal/control`、`internal/console`、`web/`；§14.3 改为控制面 API 并挂接 `CONSOLE.md`；§17.3 验收门加入 P5 控制台、原 P5 顺延为 P6；§18 路线图调整为 P4 运维后端 / P5 控制台 / P6 规则集与投产 / **P7 多站点**；§20 第 7 条「不做 GUI」作废，新增三条控制台相关未决问题；附录 C 区分控制台的已定与待定项。
- `PERFORMANCE.md`：profile 表与有界性表加入控制台内存与查询上限；内存预算加入 24 MiB 控制台项（合计 112 MiB，目标 ≤ 120 MiB）；二进制体积目标由 ≤ 12 MiB 调整为 ≤ 14 MiB（控制台静态资源）。
- `README.md`：阶段表、文档列表、设计要点、非目标同步。

### 变更（第四稿：控制台两层准入 + payload 代码模式）

- **认证拆成两层**（`CONSOLE.md` §3.1）：
  - 第一层**访问门槛（防扫描器）**：`path_token`（控制台挂在 32 位随机路径下，其他路径一律 404，不暴露存在性，**推荐**）、可叠加 `drop`（直接断连）、可选 `basic`（但 401 等于告诉扫描器这里有服务，不作首选）。另加探测封禁：同 IP 60 秒 20 次门槛失败 → 封 15 分钟。**（此条已被下面的第五稿取代：门槛改回 Basic，见「第五稿」。）**
  - 第二层**正式登录（认证）**：表单登录 + 会话，`admin.auth_mode: session` 成为默认；`session+basic` 时 Basic 只作 CLI 脚本通道。
  - 明确写清：门槛**不是安全边界**，不能当认证用；认证也不能替代门槛，否则探测流量淹没日志、暴力破解尝试次数充足。
- **payload 展示改为「绝对代码模式」**（`CONSOLE.md` §3.4）：payload 必须看得见，否则没法判断误报；但绝不作为内容参与 HTML 渲染。
  - 一律 `<pre><code>` + `textContent`，封装唯一原语 `renderCode`。
  - **全前端禁用** `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `document.write` / `eval` / `new Function`，CI 门禁 `scripts/lint.py` 卡死；开发模式运行时改写 `innerHTML` 为抛错。
  - **不引第三方 markdown 库**；自研极小 markdown 子集（代码块/表格/粗体/换行），不支持链接、图片、raw HTML。
  - 服务端先做可打印化（控制字符转 `\xNN`，UTF-8 边界截断 4 KiB），前端再 `textContent`，双层防护。
  - 列表页只显示摘要，详情页展开代码块（变换前后对比），另提供"下载原始字节"取证。
  - E2E 必须用 `<script>alert(1)</script>`、`<img src=x onerror=alert(1)>`、`javascript:alert(1)` 三条 payload 断言 DOM 无脚本、无 `on*`、无 `javascript:` 链接。
- `DESIGN.md` 附录 B 的 `admin` 配置加入 `gate` 段并把 `auth_mode` 改为 `session`；附录 C 与 §20 同步定稿。

### 变更（第五稿：Basic 作为第一层门槛）

- **第一层门槛改为 HTTP Basic 并成为默认方案**（用户提出，成立）：其价值不是"认证"，而是**不让扫描器看见门** —— 未过 Basic 时控制台监听端口上**所有路径统一返回 401，不区分路径是否存在**，扫描器既看不到登录页，也探测不出控制台路径、API 端点与产品指纹。过了 Basic 才见登录页，再走正式认证（`auth_mode: session`）。
- 明确这一层**最容易写错的点**：绝不能写成"只对 `/` 和已知 API 要 Basic，其他路径 404" —— 401/404 的差异本身就是指纹，扫描器靠它几分钟就能枚举出路径与端点。
- 401 响应不带 `Server` 头与产品特征，realm 用中性字符串（默认 `Restricted`）。
- **门槛凭据与登录账号分开**：门槛凭据只解锁登录页、不授予操作权限，可单独轮换、可交给运维同事而不暴露管理口令。
- 门槛失败与登录失败**合并计入封禁计数**；另加门槛探测封禁（同 IP 60 秒 20 次 401 → 封 15 分钟）。
- CLI 便利：带合法 `X-Donothack-Token` 的请求可配为跳过门槛。
- **TLS 变为强制**：因为门槛用 Basic（凭据是 base64 而非加密）。为不牺牲便利，**首次启动若未配证书则自动生成自签证书**（标准库 `crypto/x509`，SAN 含域名与本机 IP，有效期 1 年，到期前 30 天告警）并打印指纹；确实要明文时须显式 `admin.allow_insecure: true` 才启动。
- 随机路径 `gate.path_token` 降级为**可选额外遮挡**（Basic 已挡住路径暴露，此层只是顺手便宜）；`gate.drop` 因与 Basic 的浏览器凭据弹窗互斥而移除。
- 诚实写明该方案的固有代价：401 本身告诉扫描器"这个端口有 HTTP 认证服务"，换来的是登录页/路径/API/产品指纹全不暴露。
- `DESIGN.md` 附录 B 的 `admin` 配置同步（新增 `admin.gate` 与 `admin.tls` 段、`realm`、`exempt_api_token`）；附录 C 与 §20 同步定稿。

### 新增（P0 骨架，tag `v0.1.0-mvp`）

- **可运行的转发骨架**：`cmd/donothack`（加载配置 → 探测档位 → 设置 GC → 打印内存预算 → 反向代理 → 优雅停机）。
- `internal/config`：完整配置结构（对应 DESIGN 附录 B）、未知字段报错、`5s` / `512KiB` 这类人类可读写法、严格校验。
  **档位是上限的唯一来源**：没显式写的项由 profile 填充，`profile: small` 不会继承 medium 的连接上限。
- `internal/profile`：按 cgroup v2 → cgroup v1 → `/proc/meminfo` → 平台兜底（Windows `GlobalMemoryStatusEx`）探测，
  按 `NumCPU` 与内存选档并打印来源；生成内存预算表，校验"连接数 × 每连接预算 + 规则集 + 池 < 可用内存 60%"这条硬约束。
- `internal/proxy`：零缓冲流式转发（不做响应检测，因此不需要 body tee）；上游不可达返回 502，**绝不静默直连**；
  不信任 XFF（严格信任链留到 P3）；清掉上游回显的 `X-Request-ID`，保证客户端只看到一个值。
- `internal/server`：`MaxHeaderBytes` 压到 32 KiB、读/写/空闲超时、并发连接信号量（超限 503 + `Retry-After`）、
  `/healthz`、`/readyz`（暴露档位来源、预算、上游 DNS 可达性、在途与拒绝计数）、优雅停机 drain 在途请求、
  访问日志只记业务请求（探针不刷日志）。
- `internal/audit`：应用日志与访问/审计日志**分开输出**（前者 stderr，后者 stdout 或文件），两者共用一把写锁，避免行交错。
- 开发工具（不随发布产物分发）：`cmd/loadgen`（只用标准库的压测器）、`cmd/testupstream`（假上游）、
  `cmd/plainproxy`（**裸反向代理，公平性能基线**）。
- `scripts/lint.py` 门禁、`scripts/bench.py` 压测、`scripts/passthrough.py` 透传保真度检查；
  `Makefile`（钉死 `GOAMD64=v1`）、`deploy/donothack.service`、`config.example.yaml`。

### 新增（日志轮转与保留，P0 补齐）

压测发现"29k rps ≈ 22 MB/s、8 秒 176 MB"之后，把日志从"只追加"补成有闸门的：

- **单文件上限** `log.max_size_mb`：到量就归档（文件名带时间戳，同一秒撞名自动加后缀）。
- **保留份数 + 目录总配额** `log.max_backups` + `log.total_max_mb`：超了删最旧的。
  两份都要有 —— 份数管不了"份数 × 大小相乘"，总配额是硬顶。
  **启动时也清理一次**（只靠轮转时清理的话，长期不轮转的进程会一直堆垃圾）。
- **磁盘水位** `log.min_free_mb`（默认 1 GiB）：剩余低于它就丢弃日志并计数，**绝不再写**。
  日志的价值远低于业务可用性 —— 磁盘被日志写满会连带拖死业务与系统服务。
- **访问日志策略** `log.access_mode`：`all` / `hit`（只记非 pass）/ `sample`（非 pass 全记 + pass 按比例采样）。默认 `all`（P0/P1 无检测能力，只记非 pass 等于什么都不记），上到 block 模式后应改 `hit`。
- **轮转后异步 gzip**（单 worker，队列满就跳过、绝不阻塞写）：实测 1 MiB 文本日志压到 51 KB。
- **丢弃/轮转/删除/跳过压缩的计数进 `/readyz` 的 `log` 字段** —— 这两件事必须能被看到，否则出问题时只剩"日志怎么少了一段"。
- 端到端实测：1 MiB 单文件 + 3 MiB 总配额，6 秒 16.4 万请求 → 47 次轮转、**删除 62 个旧文件**、目录稳定在 2.26 MiB。
- 修掉一个统计语义 bug：排队等待压缩的文件被保留策略删掉时，不再计成"压缩失败"（那是配额在正常工作，不是失败）。

### 修正

- **性能基线判据修正**：原写"吞吐相对直连上游下降 < 10%"，这条**不公平** —— 直连是一跳、过 WAF 是两跳，
  同一台机器上量到的是"多了一跳代理"，不是"WAF 慢"。改为**相对裸反向代理**（`cmd/plainproxy`）比较。
  本机实测印证：medium 档直连 84272 rps、裸代理 26122 rps、donothack 28817 rps —— 相对直连掉 66%，
  相对裸代理是 -10%（落在噪声内，因为 P0 还没有检测逻辑）。
- **压测逼出一条必须提前管住的资源：审计日志的落盘速率。** P0 实测 29k rps 时约 **22 MB/s**
  （每请求一条访问日志），8 秒压测写出 176 MB —— 20 GB 磁盘十几分钟写满，而写满之后是
  "WAF 静默失能"这种最糟的失败模式。已作为 P4 强制项写入 `PERFORMANCE.md` §5.2 与 `DESIGN.md` §14.1：
  大小轮转 + 有界异步队列 + **`log.access_mode`（`all`/`hit`/`sample`，默认 `hit`）** + 落盘速率进指标。
  审计日志要留的是"被拦了什么"，不是"有多少正常请求通过"。
- 脚本从 PowerShell 换成 Python：Windows PowerShell 5.1 缺 `??`、`$IsWindows`、递归 `Select-String`，
  且默认编码是 GBK（中文输出与 UTF-8 子进程输出都会解码失败）。Python 一套脚本跨平台。

### 状态

P0 完成。下一步 P1（解析层：路径规范化、解码链、参数提取、上限控制）。

---

## 回滚参考

| 想回到 | 命令 |
| --- | --- |
| 设计稿状态 | `git checkout v0.0.1-design` |
| 查看设计与实现的差异 | `git diff v0.0.1-design..v0.1.0-mvp` |
| 撤销某次错误提交 | `git revert <sha>` |

## [2026-10-06] P2 规则引擎与规则集（tag `v0.3.0-engine`）

### 新增
- `internal/ac`：Aho-Corasick，用于算子 `pm` 与规则集共享预筛。
- `internal/transform`：30 个变换，覆盖双写 URL、`%uXXXX`、HTML 实体、JS 转义三种形态、
  base64（含缺 padding/URL-safe）、sqlHex、CSS 转义、注释分割、路径规范化。
- `internal/operator`：编译期/运行期分离的算子；字符串/数值/字节范围/IP/逻辑组合
  （深度封顶 4 层）+ 语义算子（detectSQLi、detectXSS、detectPathTraversal、
  containsShellChars、isWebshellContent、entropy、luhn）。
- `internal/rules`：YAML 加载 → 校验 → 编译 → 预筛索引；例外（reason+expires 强制、
  过期自动失效）；链式规则；规则自带正负样本的加载期自测。
- `internal/engine`：阶段流水线、按类目累计评分、detect/block/mixed 裁决；
  无阶段 2 规则时完全不读请求体。
- `internal/pipeline`：解析 → 检测 → 决策 → 放行/拦截；fail-open；拦截响应不回显 payload。
- CLI：`rules check`、`test -r req.http`、`-no-rules`。
- `rules/*.yaml` 57 条规则（9 类目）+ `testdata/corpus` 四类语料 + 两个自检脚本。
- `scripts/acceptance.py`：原始报文端到端验收。

### 修复
- **Aho-Corasick 建边持有失效切片指针**：`m.nodes` 扩容后新边写到废弃数组上直接丢失，
  症状是"某些模式永远匹配不上"。由规则集自测第一次运行时暴露。
- **预筛漏检**：含交替 `|` 的正则只提最长字面量会跳过规则（SCAN-2003、UPLOAD-1001
  实测完全没命中）。现含交替或可选组时放弃预筛，改为每请求评估。
- **detectSQLi 漏子查询注入**：`1' and (select count(*) from users)>0--` 在去注释后
  既无恒真比较也无 union。已加子查询形态指纹。
- `chain` 原来是空操作（队友报告）：拆分规则会让前一半对每个请求加分，阈值被悄悄拉低。
- 算子参数无校验导致 `depth`/`min_depth` 类笔误静默失效。
- 绝对形式 request-target（`GET http://host/path`）被当成普通路径处理。

### 已知边界（已写入文档）
- **CL+TE 请求走私在本层检测不到**：Go 的 net/http 解析后就抹掉了这两个头，
  chunked 时连 Content-Length 一起删。原 PROTO-1006/1007 是死规则，已删除。
  风险说明：Go 与反向代理会重新编码请求，歧义传不到上游。
- 无字面量规则占比 35%（语义算子），预筛收益受限；正解是规则多用 `pm`。

## [2026-10-06] P3 防护动作与决策链路（tag `v0.4.0-protect`）

### 新增
- `internal/realip`：真实 IP 严格信任链。对端不可信时**完全忽略转发头**；
  可信时从链最右往左剥离可信代理，遇到第一个不可信地址即为客户端；最多查 32 跳。
- `internal/ratelimit`：令牌桶 + 固定窗口违规计数的临时封禁。
  容量有界（LRU 淘汰，默认 8192 key，**封禁中的条目不淘汰**）；判定实测 25ns / 0 allocs。
- `internal/degrade`：过载降级 L1–L4（丢日志 / 跳昂贵算子 / 只跑阶段 1 / 旁路）。
  带滞回防抖动；三处可见（日志、`/readyz`、响应头）；
  **block 模式只允许 L1，L2+ 直接 503**，绝不放行未经检测的流量。
- `internal/blockpage`：拦截警告页。自包含（零外部资源、无 JS）、深浅色自适应、
  按客户端类型给 HTML / JSON / 纯文本三种形态；内容可在控制台自定义（自定义模板
  编译失败时回退内置页并留痕，绝不让手滑变成全站 500）；品牌展示可关。
- 规则级处置动作真正生效：`action.type: log | block | challenge | tarpit | drop`
  （原先只解析不生效）。优先级 Drop > Block > Tarpit > Challenge > Log。
  `drop` 直接断连（不支持 Hijack 时退化为拦截页）；`tarpit` 有延迟上限（默认 3s）。
- `engine.ban_on_block` / `block_ban_duration`：判定拦截时可选临时封禁来源 IP（默认关）。
- `block_page.*` 配置段；`ratelimit.max_keys`；`Config.Path` 让相对路径相对配置文件解析。

### 变更
- `scripts/passthrough.py` 默认路径去掉攻击 payload —— 带 `/etc/passwd` 的路径会被
  正确拦掉，脚本报"不一致"其实是在测检测（而且测对了）。攻击样本归 `acceptance.py`。

### 已知边界
- `challenge` 动作尚未实现（需要 JS + 签名 cookie），当前**降级为拦截**而不是放行。
- 恶意流量占满连接时，拦截页渲染是每请求一次模板执行（实测 8.6µs）；
  限速/封禁路径强制走纯文本（95ns）以避开这一点。

## [2026-10-06] P4 控制面与控制台后端（tag `v0.5.0-console-api`）

### 新增
- `internal/eventstore`：内存 ring（档位预算决定条数）+ 1440 分钟聚合桶 + 分页查询 +
  类目/来源排行。写入实测 62ns、0 allocs。payload 在**入口处一次性可打印化并按 UTF-8
  边界截断**（4 KiB），不切碎多字节字符。
- `internal/control`：控制面。单写者 + 不可变 State + `Apply`/`Preview`/`Subscribe`，
  失败即整次拒绝（旧状态一个字节不动），变更后原子推给数据面并记操作审计。
- `internal/console`：控制台后端。门槛（统一 401 + 中性 realm + 无 Server 头）、
  PBKDF2-HMAC-SHA256 60 万次会话登录、CSRF（双提交 + HMAC 签名）、
  `X-Donothack-Console` 头、Origin 校验、探测封禁、自签证书、
  静态资源 `go:embed` + `<base href>` 改写 + ETag 重新验证。
- 14 组 `/api/v1` 端点（认证/状态/指标/事件/规则/拦截页/限速封禁/配置/审计）。
- **拦截页可控制台自定义**：模板试执行校验（字段名写错也会在保存时被拒）、
  预览接口、写盘、一键恢复内置页。数据面热替换，不重启即时生效。
- `assets.go`：模块根目录的 embed 包（`go:embed` 不能引用包外路径，而 `web/` 按文档要在仓库根）。

### 修复
- **模板校验只做 Parse 不够**：`html/template` 只在执行期检查字段是否存在，
  `{.NoSuchField}` 会通过校验然后每请求静默回退内置页。现在编译期用样例数据试执行。
- **控制面版本号不推进**：改完仍是 v1，前端无法判断改动是否生效。
- `WWW-Authenticate` 一度改成手工保大写，导致 `Header.Get` 取不到 —— 退回 `Set`（RFC 允许规范化大小写）。
- CSRF 校验把"头缺失"与"值不匹配"混在一个错误码里，诊断信息对不上。

### 实测
- 门槛：`/`、`/index.html`、`/api/v1/status`、`/不存在路径`、`/assets/app.js`、`/.env`
  六条路径全部 401、realm 一致、无 `Server` 头 → 不存在 401/404 差异指纹。
- 写防护：缺头 / 缺 CSRF / 值错 / 跨站 Origin 四种情形依次 403。
- 坏模板三种形态（不存在字段、括号不闭合、引用不存在的模板）全部 422 且旧模板保留。
- 数据面：控制台保存自定义模板后，**不重启**即刻返回新页面；恢复内置页同样即时。
- 回归：语料 23/23 拦、17/17 放；透传 6/6 一致。

## [2026-10-06] P6 首轮验收：crackweb 打靶场（tag `v0.6.0-acceptance-1`）

### 验收结果（详见 docs/ACCEPTANCE.md）
- 扫描器 crackweb 1.6.4，crawl depth 2 / max-pages 25 / rate 40，两轮参数一致。
- 直连基线 14 findings（注入类 4：反射型 XSS ×1、SSTI ×3）→ 经 WAF 14 findings（注入类 3）。
- **反射型 XSS 归零**；补上 SSTI 规则后定点复测 XSS 端点 0 条注入类。
- 语料 23/23 拦、17/17 误报为零；透传 6/6 一致。

### 新增
- `rules/70-ssti.yaml`：SSTI 规则（原先 59 条规则里**完全没有这一类** —— 只有真跑扫描器
  才能发现"整整一类攻击没规则"）。不匹配 `{...}` 本身（会打死正常模板文案），
  只匹配"括号里在做运算或访问引擎内部对象"的形态。
- `rules/75-probe.yaml`：表达式求值探测识别（score 2，**只记分不拦**）。
  裸算术在正常业务里太常见（`?resolution=1920*1080`），拦截的误报代价远大于收益。
- `upstream.allowed_hosts`：Host 头白名单（支持 `*.example.com`），命中即 400 且不回显 Host。
  实测伪造 Host 被拒、正常 Host 放行。默认留空不校验。
- 控制面补全：`/rulesets/preview`（干跑差异）、`/events/stream`（SSE）、
  `/events/export`、`/exceptions` CRUD、`/ip-lists` CRUD、`/backup` + `/restore`（带 preview）。
- 事件存储加订阅（有界，最多 8 个订阅者，跟不上就丢事件 —— 绝不阻塞数据面）。
- IP 名单进数据面：拒绝名单命中即拦；允许名单命中跳过检测与限速
  （**刻意不对称**：允许名单不是"只允许这些 IP"，那种语义配错一次就是全站不可用）。

### 已知边界（如实记录，不含糊）
- **裸算术表达式求值**（`a=1999*1999`）在请求侧无法与正常算术参数区分，
  未拦截；已做到"可见不误伤"。治本需要响应侧检测，而本项目按设计只做请求侧。
- `exposed-path`（swagger 暴露）、`passive-*`（缓存头/Cookie 属性/安全头/明文传输）
  属应用与传输层问题，给了定位与处置建议。

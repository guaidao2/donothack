# donothack

一个用 Go 写的 Web 应用防火墙（WAF），以独立反向代理形态部署在业务服务之前，单二进制、无 CGO。

二进制名 `donothack`，模块路径 `donothack`。

**检测范围：只做请求侧** —— 判断请求头、请求体与参数里有没有攻击 payload。响应侧不检测、不缓冲、不修改，直接流式透传。

## 当前状态

**P5 已完成**（tag `v0.7.0-console-wired`）：前端在**真实浏览器**里与后端跑通 ——
八个页面全部正常渲染、0 个"后端未定义"、payload 以代码模式（纯文本节点）展开。
联调中修掉 7 处前后端字段契约不一致（详见 docs/CONSOLE.md §13）。
**P6 进行中**（tag `v0.8.0-perf-gate`）：性能门禁实测通过 —— 相对裸反向代理基线
**快 28.8%**（35332 vs 27429 rps），RSS 44.2 MiB。首轮 crackweb 验收见
[ACCEPTANCE.md](docs/ACCEPTANCE.md)：反射型 XSS 归零、SSTI 模板形态全拦，
残余 1 条裸算术形态已如实记录（请求侧无法与正常算术参数区分）。

未完成项：`BenchmarkEngine_NoMatch` 的 0 allocs/op 门禁（实测 21）、
真机 2C2G 基线、`/totp/enroll` 与 `/notify`、第二轮完整扫描。

至此 P0–P5 全部完成；P6 首轮验收见 [ACCEPTANCE.md](docs/ACCEPTANCE.md)。

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| P0 | 骨架：配置、profile 探测与内存预算、GC 控制、纯转发代理、访问日志、健康探针、优雅停机、压测与保真度脚本 | **已完成（`v0.1.0-mvp`）** |
| P1 | 解析层：路径规范化、零分配参数解析、值级展开 | **已完成（`v0.2.0-parser`）** |
| P2 | 规则引擎：DSL、变换链、算子、变换链去重与共享预筛 | **已完成（`v0.3.0-engine`）** |
| P3 | 决策：评分、模式切换、拦截动作、限速防护、真实 IP、过载降级 | **已完成（`v0.4.0-protect`）** |
| P4 | 运维后端：`control` 契约、事件存储、指标、完整 `/api/v1`、认证与审计 | **进行中（`v0.5.0-console-api`）** |
| P5 | **Web 控制台**：八个页面、原生 ES module SPA、embed 内嵌 | **已完成（`v0.7.0-console-wired`）** |
| P6 | 规则集、误报治理、真机压测基线、SecRules 兼容层评估 | 未开始 |
| P7 | 多站点（雷池式）：Host 路由、站点级规则与证书 | 后置 |

### P0 实测（本机 Windows，24 核 / 16 GiB，32 并发，8 秒，medium 档）

| 指标 | 直连上游 | 裸反向代理 | donothack |
| --- | --- | --- | --- |
| RPS | 84272 | 26122 | 28817 |
| P99 | 1.61ms | 3.28ms | 2.74ms |
| RSS | — | — | 29.6 MiB |

裸反向代理（`cmd/plainproxy`）才是公平基线：直连是一跳、过 WAF 是两跳。
相对裸代理的开销落在测量噪声内 —— **这是应该的，因为 P0 还没有检测逻辑**。
检测引入后的真实开销从 P2 开始才有意义。报告见 `docs/bench/`。

透传保真度：对真实站点（7 个请求，含 404、静态资源、带 query 的 GET、表单 POST）
逐项比对状态码、响应体哈希、Content-Type 与响应头，**全部一致**。

### P2 语料验收（本地靶场，block 模式）

原始 HTTP 报文直接打进 WAF（`scripts/acceptance.py`，裸 socket，不用 HTTP 库 ——
否则重复头与矛盾头会被规范化掉，等于没测到要测的东西）。

| 语料 | 判据 | 结果 |
| --- | --- | --- |
| `positive/`（23） | 必须被拦（403） | 23/23 |
| `negative/`（17） | 必须放行 | 17/17（零误报） |
| `detect/`（1） | 单一弱信号，设计上只记分 | 1/1 未被拦 |
| `known-gap/`（1） | 本层结构上检测不到 | 见目录 README 的原因说明 |

规则集自检：57 条规则的正负样本全过；变换链去重后 14 条；37 条可预筛、20 条每请求评估。


### P3 防护动作验收（本地靶场）

| 项目 | 实测 |
| --- | --- |
| 限速 | 白名单摘掉后连打 300 个正常请求：156 放行 / 144 个 429，带 `Retry-After` |
| 拦截页（浏览器） | `Accept: text/html` → 403 + 自包含 HTML 页（类目「SQL 注入」、请求 ID、站点、品牌） |
| 拦截页（API） | `Accept: application/json` → 403 + `{"error":"blocked","request_id":...}` |
| 拦截页（命令行） | 无 Accept → 403 + 纯文本（洪泛路径不渲染模板） |
| 透传保真度 | 6/6 一致 —— 代理没有改动上游语义 |
| 语料回归 | positive 23/23 拦、negative 17/17 放、detect 1/1 符合设计 |


## 文档

- [架构设计](docs/DESIGN.md) —— 总体架构、模块划分、关键接口、数据结构、阶段划分与验收标准
- [Web 控制台设计](docs/CONSOLE.md) —— 控制面/数据面分离契约、八个页面、`/api/v1`、认证与安全、无构建链的前端方案、事件存储分层
- [性能预算与低配部署](docs/PERFORMANCE.md) —— **硬约束文档**：profile 分级、每请求 CPU/内存预算、热路径零分配、变换链去重与共享预筛、GC 与内存控制、构建参数、降级策略、性能门禁
- [规则 DSL 规格](docs/RULES.md) —— 规则文件格式、变量集合、变换、算子、例外机制、离线测试
- [变更日志](CHANGELOG.md)

## 首要约束：低配 VPS 也要能跑

目标机型 **2 vCPU / 2 GiB**，最低支持 **1 vCPU / 512 MiB**。这条约束决定了实现方式：

- **热路径零分配**。核少时 GC 是主要 CPU 消耗，`BenchmarkEngine_NoMatch` 硬门禁 0 allocs/op，端到端 donothack 自身新增分配 ≤ 2 allocs/req。
- **变换链去重 + 共享 Aho-Corasick 预筛**。300 条规则归一化后通常只有 5~10 条不同变换链，每链每值只算一次、只扫一次，命中候选才跑昂贵算子。
- **响应零缓冲**。不做响应检测，响应不进内存直接透传 —— 这是范围收窄换来的最大性能收益。
- **逐项有界**。请求体、连接数、参数个数、限速表容量全部有上限。**无界即漏洞** —— 伪造源 IP 喷洒就能把内存打爆。
- **分级 profile**。`small` / `medium` / `large` 按 cgroup 自动探测，档位决定检查上限、连接上限、规则集上限、`GOGC` 与 `GOMEMLIMIT`。
- **有界降级**。过载时按 L1–L4 分级降级，状态必须进日志、指标与 `/readyz`；`block` 模式只允许 L1，其余情况返回 503 而不是悄悄放行。
- **构建钉死 `GOAMD64=v1`**。低配 VPS 的 CPU 常常不支持 AVX2，`v3` 会直接 `illegal instruction` 崩掉。

## 设计要点（速览）

- **变量集合抽象**：所有输入来源（query / form / JSON / XML / multipart / cookie / header）统一拆平成扁平命名空间，规则只对着命名空间匹配，各类编码绕走在解析层被统一消化。
- **评分制而非硬拦**：按类目累积分，达到阈值才拦，避免"一个单引号封站"。
- **fail-open**：任何解析或规则异常都放行并留审计，WAF 绝不成为业务单点故障。
- **变换链去重 + 共享字面量预筛**：全部规则的字面量汇入同一个 Aho-Corasick 自动机，变换链归一化去重（300 条规则通常只有 5~10 条不同链），每链每值只算一次、只扫一次，命中候选才跑昂贵算子。这是性能的主要来源。
- **零停机热加载**：规则集不可变 + `atomic.Pointer` 原子替换，加载前跑内置正负语料自测，失败自动回滚。
- **检测模式先行**：默认只记录不拦截，用真实的规则命中数据决定哪条规则够格进拦截档。
- **Web 控制台**：对标雷池，浏览器里看攻击、查事件、启停规则、加白名单、调限速、改配置、看操作审计。控制面与数据面严格分离 —— 数据面只读不可变快照，所有写操作走 `control.Apply`（校验 → 自测 → 原子替换 → 失败回滚）。前端是原生 ES module SPA，无 Node 构建链。
- **控制台两层准入**：第一层 HTTP Basic 门槛挡扫描器 —— 未过 Basic 时**所有路径统一 401**（不区分存在与否），登录页、路径、API、产品指纹整体不可见；第二层表单登录 + 会话做真正的认证。门槛凭据与登录账号分开、可单独轮换。因门槛用 Basic，TLS 强制，未配证书时首次启动自动生成自签证书。
- **payload 用绝对代码模式展示**：一律 `<pre><code>` + `textContent`，全前端禁 `innerHTML`（CI 门禁卡死），不引第三方 markdown 库。既看得见 payload 能判误报，又不给自己种存储型 XSS。

## 目标性能（`medium` profile，2 vCPU / 2 GiB）

以下为**目标值**，须在真机 VPS 上实测确认后才算达成，未经实测不作为承诺。

- 纯转发 GET：附加延迟 P50 < 0.15ms，P99 < 0.5ms
- 1 KiB body + 全规则评估：P99 < 1.5ms
- 吞吐 ≥ 8000 rps，**相对裸反向代理**降幅 < 10%（相对直连的降幅只作参考）
- 空载常驻 < 25 MiB，满负载 < 120 MiB，压测 30 分钟 RSS 稳定
- reload 期间零失败请求

`small`（1 核 512 MiB）保底线：≥ 3000 rps、满负载 < 48 MiB。门禁与测量方法见 [PERFORMANCE.md](docs/PERFORMANCE.md) §10。

## 开发约定

```bash
# 提交前必须全绿（格式 + vet + 测试 + 前端 DOM 写入禁令）
python scripts/lint.py

# 端到端压测：直连 / 裸反向代理 / donothack 三者对比，报告写入 docs/bench/
python scripts/bench.py --profile medium --duration 20s --concurrency 64

# 透传保真度：确认代理没有改动上游语义（P1 起每次改解析层都要跑）
python scripts/passthrough.py --direct http://127.0.0.1:8787 --waf http://127.0.0.1:18080

# 跨平台编译（无 CGO；GOAMD64 必须是 v1，低配 VPS 的 CPU 常不支持 AVX2）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags="-s -w" -o dist/donothack-linux-amd64 ./cmd/donothack

# 看看当前档位与内存预算表
./dist/donothack -c config.example.yaml -print-budget
```

脚本用 Python 而不是 PowerShell：Windows PowerShell 5.1 缺一堆语法
（`??`、`$IsWindows`、递归 `Select-String`），Python 一套脚本在 Windows 与低配
Linux VPS 上行为一致。

Git 工作流见 `docs/DESIGN.md` §19：`main` 只接全绿的提交，功能走 `feat/<阶段>-<模块>` 分支，每个里程碑打 tag，回滚用 `git checkout <tag>`。

## 非目标

不做响应侧检测（本轮范围只做请求侧）、不做多站点（P7 后置）、不做多上游负载均衡编排、不做 DDoS 清洗、不做缓存/CDN、不做分布式威胁情报协同、不引入 PCRE/CGO 依赖、不引外部数据库（InfluxDB/ES）、不引 Node 构建链。

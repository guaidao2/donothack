# 性能预算与低配部署

> 状态：待评审
> 配套：`docs/DESIGN.md`
> **本文是硬约束文档。** 与本文冲突的实现一律视为缺陷。

---

## 0. 前提

首要约束：**wafd 必须能在低配 VPS 上稳定跑起来，并且不能把宿主机的延迟和内存吃穿。**

最低支持规格：**1 vCPU / 512 MiB 内存 / 机械或廉价 SSD / 无 AES-NI 也要能跑**。

这条约束改变了很多设计决策。1 核环境和 4 核环境最大的区别不是"慢 4 倍"，而是：

- **没有并行度可借**。所有优化只能是"少干活"，不能是"多核分摊"。
- **GC 成为主要 CPU 消耗**。Go 的 GC 是并发的，1 核上它和业务抢同一个核。分配越少，GC 越少，吞吐越高。**所以"零分配"在低配下不是洁癖，是性能策略的核心。**
- **内存上限是硬的**。512 MiB 的机器通常还跑着别的服务（Web 服务、数据库），wafd 自己不能超过 48 MiB。
- **慢速攻击会直接打爆内存**。每个连接都有自己的读缓冲、写缓冲、事务对象，连接数不设上限，攻击者用 1000 个半开的连接就能把 VPS 打挂。

---

## 1. 性能分级（profile）

三档 profile，启动时按 cgroup 自动探测，可显式覆盖（`profile: small|medium|large|auto`）。

| 项 | `small` | `medium` | `large` |
| --- | --- | --- | --- |
| 目标机器 | 1 vCPU / 512 MiB–1 GiB | 2 vCPU / 2 GiB | 4+ vCPU / 8 GiB+ |
| 空载常驻内存目标 | < 15 MiB | < 40 MiB | < 80 MiB |
| 满负载内存目标 | < 48 MiB | < 200 MiB | < 600 MiB |
| 硬内存上限（GOMEMLIMIT） | 容器内存 × 50% | × 60% | × 70% |
| GOGC | 200 | 200 | 100 |
| 请求体检查上限 | 128 KiB | 512 KiB | 1 MiB |
| 响应体检查上限 | 8 KiB（仅文本） | 256 KiB | 512 KiB |
| 阶段 4（响应体检测） | 默认关（可开） | 默认开 | 默认开 |
| HTTP/2 与 h2c | 默认关 | 默认开 | 默认开 |
| 最大并发连接 | 256 | 1024 | 4096 |
| 上游空闲连接/主机 | 16 | 64 | 256 |
| 规则集条数上限 | 400 | 2000 | 10000 |
| 预筛字面量上限 | 20000 | 60000 | 200000 |
| 命中事件 ring buffer | 256 | 1024 | 4096 |
| 限速状态表容量上限 | 8192 key | 65536 key | 262144 key |
| 审计日志输出 | stdout（交 journald） | 文件 + 轮转 | 文件 + 轮转 |
| TLS 终止 | 支持，但建议前置 CDN/nginx | 支持 | 支持 |

**自动探测**：读 cgroup v2 `memory.max` / `cpu.max`，退化到 cgroup v1，再退化到 `/proc/meminfo` + `runtime.NumCPU()`。探测结果写进启动日志与 `/readyz` 详情，方便排查"为什么规则没生效"（小 profile 会拒载超限规则集）。探测不到时按 `small` 保守处理。

---

## 2. 性能目标（量化，可验收）

以下为**目标值**，需要在目标机器上实测确认后才算达成。未经实测的数字不作为承诺。

### 2.1 `small` profile（1 vCPU / 512 MiB）

| 场景 | 目标 |
| --- | --- |
| 纯转发，GET 无 body，无规则命中 | 附加延迟 P50 < 0.15ms，P99 < 0.5ms |
| 1 KiB body + 全规则评估，无命中 | 附加延迟 P99 < 1.5ms |
| 命中拦截（不转发上游） | P99 < 1ms |
| 吞吐（1 KiB GET，keep-alive，1 核） | ≥ 3000 rps |
| 吞吐下降（相对直连上游） | < 10% |
| 空载常驻内存 | < 15 MiB |
| 满负载内存 | < 48 MiB |
| 压测 30 分钟后 RSS | 稳定，无单调增长 |
| reload 期间 | 零失败请求、零连接中断 |

### 2.2 每请求 CPU 预算（1 vCPU @ 3GHz，3000 rps ⇒ 每请求 333µs 总预算）

wafd 自身应控制在 **100µs 以内**，其余留给业务与内核：

| 环节 | 预算 |
| --- | --- |
| 连接与协议处理（net/http） | 25µs |
| 解析与归一化 | 20µs |
| 全规则评估（含变换链与预筛） | 40µs |
| 决策与审计编码 | 10µs |
| 代理与上游转发 | 15µs |

超预算的环节用 pprof 定位，不允许"大概慢一点没关系"。

### 2.3 内存预算（512 MiB 机器）

```
规则集（400 条 + AC 自动机）        ≤ 8 MiB
预筛自动机                          ≤ 4 MiB
并发连接 256 × 每连接 16 KiB        ≤ 4 MiB
事务对象池 + 缓冲池                  ≤ 4 MiB
限速/封禁状态表 8192 key            ≤ 1 MiB
命中 ring buffer 256 条             ≤ 1 MiB
审计输出缓冲                        ≤ 1 MiB
Go 运行时自身 + 栈                  ≤ 12 MiB
────────────────────────────────────────────
合计目标                            ≤ 48 MiB
```

**硬约束**：`并发连接上限 × 每连接内存预算 + 规则集 + 池` 必须小于可用内存的 60%，否则启动时拒绝并报错，不要等跑起来再 OOM。

---

## 3. 热路径零分配（低配下的核心策略）

### 3.1 硬指标

- `BenchmarkEngine_NoMatch`（预热后）：**0 allocs/op**。
- 端到端热路径（GET 无 body、无命中）wafd 自身新增分配：**≤ 2 allocs/req**（不含 `net/http` 内部）。
- `BenchmarkParseQuery`：**0 allocs/op**。
- `BenchmarkTransformChain`：每值每链 **≤ 1 allocs**（输出 buffer 从池取，不计）。

门禁方式：benchmark 里用 `testing.AllocsPerRun` 断言，超标 CI 直接失败。**这条不能靠自觉。**

### 3.2 具体手段

| 禁止 | 替代 |
| --- | --- |
| `net/url` 的 `ParseQuery`（每参数多次分配） | 自写零分配 query 解析器，写入池化 `[]byte` + 预建键索引 |
| `strings.Split` / `Fields` / `Cut` | 手写字节扫描，索引切片 |
| `fmt.Sprintf`（热路径） | `strconv.AppendInt` / `AppendQuote` 写入池化 buffer |
| `string(b)` / `[]byte(s)` 转换 | 全程 `[]byte`，只在日志边界转换 |
| 常规字面量匹配用 `regexp` | `bytes.Index` / Aho-Corasick；大小写不敏感用 256 字节折叠查表 |
| `bytes.ToLower` / `strings.ToLower` | ASCII 折叠查表（无分配，无 Unicode 开销） |
| 每请求 `append` 到 nil slice | 事务对象内预分配小数组（栈上）+ 溢出时用池化大数组 |
| 每请求多次 `time.Now()` | 请求开始时取一次，全链路复用 |
| 每请求起额外的 goroutine | 审计用固定 worker + 有界 channel；限速用当前 goroutine |

### 3.3 对象池

- 池化对象：`Transaction`、`Collections`、参数解码 buffer、变换输出 buffer、审计序列化 buffer、JSON 解析器状态。
- 归还时 `reset()`，**不得保留对请求 body 的引用**（否则整个 body 无法回收，这是池化最常见的泄漏点）。
- 池的 `New` 函数不做重活；启动时预热一次，避免首波请求触发大量分配。
- 池命中率进指标（`wafd_pool_hits_total`），命中率低于 90% 说明对象在别处被持有，要查。

---

## 4. 变换链去重 + 单次 AC 扫描

**这是低配下最重要的算法优化。** 朴素做法（每条规则各自跑自己的变换链、各自匹配）在 1 核上是灾难：300 条规则 × 平均 4 次变换 = 每请求 1200 次字符串处理。

### 4.1 编译期

1. 统计所有规则的 `transforms` 链，**归一化去重**，得到"不同链集合"。实践中 300 条规则通常只有 5~10 条不同的链。
2. 把所有规则的字面量模式（`pm` 的词表、`regex` 提取的最长字面量子串、`contains`/`eq` 的值）汇入**一个共享的 Aho-Corasick 自动机**。
3. 自动机的每个终态映射到规则位图（`[]uint64`，规则数 / 64 个 word）。
4. 无法提取字面量的规则（`entropy`、`validateByteRange`、`luhn`、纯 `detectSQLi` 等）归入"**廉价算子组**"，不进预筛，直接执行——它们本身足够便宜，且预筛对它们无效。

### 4.2 运行期（每个变量值）

```
原始值 ──┬─▶ 链 A 变换 ──▶ AC 扫描 ──┐
         ├─▶ 链 B 变换 ──▶ AC 扫描 ──┤
         ├─▶ 链 C 变换 ──▶ AC 扫描 ──┼─▶ 候选规则位图（无分配）
         │  …（不同链通常 5~10 条）   │
         └─▶ 廉价算子组 ──────────────┘
                                      │
                                      ▼
                            只对候选规则跑昂贵算子
```

- 每个**不同链**只计算一次、只扫描一次。
- 位图用 `uint64` 位运算合并，零分配。
- 昂贵算子（正则、`detectSQLi`、`detectXSS`）只对候选规则执行。

**收益**：变换次数从 `O(规则数 × 链长)` 降到 `O(不同链数)`；算子执行从 `O(规则数)` 降到 `O(候选数)`。

**代价与上限**：

- 预筛假阳性意味着少数规则被白白执行 —— 这是可接受的（比漏检好）。
- 自动机内存：1 万条字面量约 2–4 MiB。超过 `max_prefilter_literals` 的字面量不并入自动机，其所属规则标记为"无预筛"，直接执行并在启动日志里列出数量。
- **超长值处理**：值超过 8 KiB 时，只对前 8 KiB 跑完整变换链与 AC 扫描，尾部只跑廉价算子。这是明确的取舍：超长参数的尾部攻击可能漏检，但超长参数本身会触发 `PROTO` 规则记分。必须在审计里标记 `truncated_scan: true`。
- **字面量长度下限 3 字节**：更短的字面量（`1`、`a`、`..`）会让自动机几乎在任意输入上命中，预筛等于失效，反而比不预筛更慢。这类规则被标记为"无预筛"直接执行，编译期统计占比，超过规则集 20% 时告警（规则侧约束见 `docs/RULES.md` §9.2 第 9 条）。
- **恒真规则是性能毒药**：规则集里只要有一条"对每条请求都命中"的规则，候选集就永远是全集，预筛彻底失效。编译期检测并告警。

### 4.3 惰性

- 阶段 1 不读请求体。没有阶段 2 规则时，body 完全不解码（配置错误导致的"规则没生效"不会变成性能灾难）。
- 同一 target 在一个阶段内只展开一次。
- 命中即够阈值时立刻短路，不再评估剩余规则（`hard_block` 立即终止阶段）。

---

## 5. GC 与内存控制

### 5.1 启动时

```go
// 1. 探测 cgroup 内存上限，取 profile
// 2. 设置软内存上限，让 GC 在接近上限时变激进，而不是被 OOM Killer 干掉
debug.SetMemoryLimit(int64(limitBytes * profile.MemLimitRatio))

// 3. 低配下抬高 GOGC，减少 GC 次数（内存由 GOMEMLIMIT 兜底）
debug.SetGCPercent(profile.GOGC)   // small: 200
```

`GOMEMLIMIT` 与 `GOGC` 配合使用，而不是二选一。单独抬 GOGC 会让内存无限涨；单独设 GOMEMLIMIT 而 GOGC 保持 100 会让 GC 过于频繁、白烧 CPU。

### 5.2 有界性（每一样都要有上限）

| 资源 | 上限 | 超限行为 |
| --- | --- | --- |
| 请求体检查 | profile 值 | 截断 + 标记 + 指标 |
| 响应体检查 | profile 值 | 截断 + 标记 + 指标 |
| 并发连接 | profile 值 | 信号量满则 503（可配直接断连） |
| 单连接读缓冲 | 32 KiB（含头） | net/http 层限制 |
| 限速/封禁状态表 | profile 值 key 数 | LRU 淘汰最旧 |
| 命中 ring buffer | profile 值条数 | 覆盖最旧 |
| 审计队列 | 4096 条 | 丢弃并计数（**绝不阻塞请求**） |
| 规则集条数 | profile 值 | 启动/reload 直接拒绝 |
| 预筛字面量 | profile 值 | 超出部分不进自动机 + 告警 |
| 参数个数 | 默认 1000 | 超出不解析，记 `PROTO` 分 |
| 单参数值长度 | 默认 64 KiB | 截断参与检测 |
| JSON 深度 / 节点数 | 32 / 10000 | 停止展开 |
| 解码迭代次数 | 8 层 | 停止并记 `PROTO` 分 |
| 解压输出 | min(声明, 检查上限 × 4) | 停止并记 `PROTO` 分 |
| 单请求总时限 | profile 值（small 15s） | 中断 |

**限速状态表必须有容量上限**：否则攻击者伪造源 IP 喷洒，把内存打爆。这一点和"必须有界"是同一个道理。

### 5.3 reload 的内存峰值

reload 时新旧规则集共存，峰值内存 = 2 × 规则集 + 2 × 预筛自动机。`small` profile 下规则集上限 400 条，峰值约 24 MiB，安全。启动时按此校验并打印预算表。

---

## 6. 连接、超时与协议层

| 参数 | `small` | 说明 |
| --- | --- | --- |
| `MaxHeaderBytes` | 32 KiB | net/http 默认 1 MiB，低配下太大，是内存放大点 |
| `ReadHeaderTimeout` | 5s | 防 slowloris |
| `ReadTimeout` | 15s | 含 body |
| `WriteTimeout` | 30s | |
| `IdleTimeout` | 60s | keep-alive 复用，别太长占内存 |
| 最大并发连接 | 256 | 信号量 |
| 上游 `MaxIdleConnsPerHost` | 16 | |
| 上游 `IdleConnTimeout` | 30s | |
| `TCP_NODELAY` | 开 | 禁用 Nagle，降低小响应延迟 |

**保留零拷贝快路径**：大 body 透传时不要包一层会把 `ReadFrom`/`WriteTo` 吃掉的自定义 reader —— Go 在 Linux 上对 `net.TCPConn` 有 splice 快路径，包错一层就从 splice 退化成用户态拷贝。实现 body tee 时必须显式实现 `io.WriterTo` / `io.ReaderFrom` 并转发到内层。

---

## 7. 构建与部署参数

### 7.1 构建

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags="-s -w -X donothack/waf/internal/version.Version=$VER" \
  -o dist/wafd-linux-amd64 ./cmd/wafd
```

- **`GOAMD64=v1` 必须是 v1。** 低配 VPS 的 CPU 经常是老型号，`v3` 需要 AVX2，跑起来直接 `illegal instruction` 崩掉。默认值就是 v1，但要在 Makefile 里显式钉死，防止有人手滑。
- 同时产出 `linux/arm64`（Oracle/Ampere 免费机型常见），成本为零。
- 目标二进制 ≤ 12 MiB（strip 后）。依赖只有标准库 + `yaml.v3`。
- **不用 UPX**：会破坏 `-trimpath` 的可调试性，某些 VPS 的杀软还会误报。要做成可选开关，默认关。

### 7.2 systemd 单元模板（随仓库提供）

```ini
[Service]
ExecStart=/usr/local/bin/wafd -c /etc/wafd/config.yaml
Restart=always
RestartSec=1
LimitNOFILE=8192
MemoryMax=384M          # 硬顶，超了只杀 wafd 不拖垮整机
CPUQuota=90%
OOMScoreAdjust=200      # 宁可先杀 wafd，也别让业务跟着倒霉
StandardOutput=journal
StandardError=journal
# 不用自写文件轮转：journald 更省 CPU 与磁盘
```

要点：`MemoryMax` 给 wafd 一个硬天花板，配合 `GOMEMLIMIT`（软）形成双保险 —— 软限让 Go 自己 GC，硬限是最后一道。`OOMScoreAdjust` 是关键：整机内存紧张时优先杀 wafd，保证业务活着。这符合"WAF 不能成为单点故障"的原则。

### 7.3 Docker

```bash
docker run -d --memory=384m --cpus=1 --ulimit nofile=8192 -p 80:8080 wafd
```

镜像用 `scratch` 或 `gcr.io/distroless/static`，不带 shell、不带包管理器，镜像 < 20 MiB。

---

## 8. 降级策略（过载保护）

低配机器最怕的不是"慢"，是**雪崩**：WAF 抢光 CPU → 业务超时 → 重试 → WAF 更忙。

降级必须**分级、可见、可配**：

| 级别 | 触发条件 | 动作 |
| --- | --- | --- |
| L0 正常 | — | 全功能 |
| L1 丢日志 | 审计队列满 | 丢弃日志并计数（已有设计） |
| L2 关阶段 4 | 请求队列延迟 P99 > 50ms 持续 10s | 停响应体检测，保留响应头 |
| L3 只跑阶段 1 | 持续 30s 未恢复 | 停请求体解析与阶段 2，只跑扫描器/协议规则 |
| L4 旁路 | 持续 60s 未恢复 | 纯转发，只记录，不检测 |

**硬性约束**：

- 降级状态必须体现在三处：结构化日志（`level=alert`）、指标（`wafd_degraded_level`）、`/readyz` 详情。**静默降级等同于 WAF 悄悄失效，不可接受。**
- **`block` 模式下禁止自动降级到 L3/L4。** 理由是：选择 block 模式意味着部署方把安全放在可用性之前，此时静默放行是背叛预期。block 模式过载时应返回 503（拒绝服务而不是放行攻击），并把决定权交给部署方通过配置调整。
- `detect` 模式可自动降级到 L4（反正本来就不拦）。
- 配置项 `engine.degrade: auto | off`，默认 `auto`（small profile）/ `off`（medium、large）。
- 每次降级/恢复都写审计，`/admin/events` 可查。

---

## 9. 低配上的明确取舍

诚实列出低配下放弃了什么，避免误以为"什么都能要"：

| 放弃 | 原因 | 影响 |
| --- | --- | --- |
| 响应体全量检测 | 需缓冲整个响应体，内存与 CPU 都不划算 | `small` 下只扫前 8 KiB 文本，可能漏掉响应尾部的泄露 |
| HTTP/2 与 h2c | 每流状态开销大，1 核上不划算 | 只支持 HTTP/1.1（含 keep-alive）；前置 CDN 时可不开 |
| PCRE / 完整 ModSecurity 语义 | 需 CGO 或庞大解释器 | SecRules 兼容层只做子集（见 RULES.md §11） |
| 超长值尾部深检测 | 变换链与扫描有长度上限 | > 8 KiB 的值只扫前 8 KiB，尾部靠廉价算子 |
| payload 全量留存 | 内存与磁盘都不可接受 | 只有 256 条 ring buffer 摘要，需要取证时开 `capture_payload` |
| 多上游编排 / 服务发现 | 与低配无关，但增加复杂度与内存 | 单上游 |
| 分布式限速协同 | 需 Redis 常驻连接与内存 | 单机内存限速 |

### 什么情况下这台机器不该跑 wafd

- 内存 < 512 MiB：Go 运行时 + 规则集 + 连接缓冲自己就吃掉大半，剩给业务的太少。
- 1 vCPU 但是严重超售的共享核：附加延迟会从 0.5ms 涨到几毫秒，量级不对。
- 上游是静态站点或有 CDN 兜底：此时 wafd 的收益低于它的延迟成本，应把 WAF 放到 CDN 边缘。

遇到这些情况，方案是前置 CDN 或升级 VPS，不是把 wafd 的参数调到极限硬塞。

---

## 10. 性能验证方法与门禁

### 10.1 微基准（进 CI，硬门禁）

```
BenchmarkEngine_NoMatch        0 allocs/op，< 20µs/op
BenchmarkEngine_FullRules      候选规则数 < 10，< 45µs/op
BenchmarkParseQuery            0 allocs/op
BenchmarkTransformChain        每链 ≤ 1 allocs
BenchmarkACScan                < 8µs / 1KiB 值
BenchmarkAuditEncode           ≤ 1 allocs/op
BenchmarkProxyPassthrough      ≤ 2 allocs/op（wafd 自身）
```

### 10.2 端到端

`scripts/bench.ps1`（Windows）/ `scripts/bench.sh`（Linux）：

1. 起 `httptest` 假上游（固定 200 + 1 KiB body）。
2. 起 wafd（指定 profile）。
3. 用 `hey` 或 `wrk` 分别压直连上游与经过 wafd，压 60s。
4. 采集 RPS、P50/P90/P99、wafd RSS、CPU 占用、GC 次数（`/metrics` 或 `runtime/metrics`）。
5. 输出对比表，写入 `docs/bench/<tag>-<profile>.md`。

**报告进版本库，原始数据不进**（`.gitignore` 已排除）。

### 10.3 受限环境模拟

没有目标 VPS 时，先在本机模拟出主要约束：

```powershell
# Windows：限制到 1 个 P、48 MiB 软内存上限
$env:GOMAXPROCS=1; $env:GOMEMLIMIT=48MiB
```

```bash
# Linux：cgroup 精确限制
systemd-run --scope -p MemoryMax=384M -p MemoryHigh=320M -p CPUQuota=100% \
  ./dist/wafd -c bench/config-small.yaml
```

**诚实说明**：`GOMAXPROCS=1` 能模拟单核的调度行为，`GOMEMLIMIT` 能模拟内存压力，但**模拟不出真实 VPS 的 CPU 型号、磁盘 IO 与网络栈**。最终数字必须在真机 1 核 VPS 上跑一次才算数，跑法：

```bash
curl -sSL <仓库>/scripts/bench.sh | bash -s -- --profile small --duration 60
```

结果贴回仓库 `docs/bench/`，作为该 profile 的基线。

### 10.4 剖析（优化时用）

- `net/http/pprof` 挂在管理端口（`127.0.0.1:9091/debug/pprof/`），**不暴露到公网**，默认关，`admin.pprof: true` 才开。
- 定位顺序：先看 `allocs`（`-benchmem`），再看 `pprof -alloc_space`，最后才看 `cpu`。低配下 80% 的问题出在分配，不是算法。
- GC 调优前先跑 `GODEBUG=gctrace=1`，确认 GC 频率与暂停时间，别凭感觉调 `GOGC`。

---

## 11. 待确认

- [ ] 目标 VPS 的确切规格（vCPU / 内存 / 架构 / 是否自行终结 TLS）。
- [ ] 默认 profile 是否就按 `small` 作为最低支持线（即 512 MiB 是底线，不再往下压）。
- [ ] 阶段 4 在 `small` 下默认关（只查响应头 + 前 8 KiB 文本），是否接受。
- [ ] 审计日志 `small` 默认走 stdout 交 journald（不自写文件轮转），是否接受 —— 这需要机器上有 systemd。
- [ ] 降级策略：`small` 默认 `auto`、`block` 模式禁止降级到 L3/L4，是否认可。
- [ ] 是否提供真实 VPS 做一次基线测量（没有的话，第 2 节的目标值只能标记为"未经实测"）。

# 性能预算与低配部署

> 状态：待评审
> 配套：`docs/DESIGN.md`
> **本文是硬约束文档。** 与本文冲突的实现一律视为缺陷。

---

## 0. 前提

首要约束：**donothack 必须能在低配 VPS 上稳定跑起来，并且不能把宿主机的延迟和内存吃穿。**

**目标机型：2 vCPU / 2 GiB（`medium` 档）。最低支持线：1 vCPU / 512 MiB（`small` 档）。**

这条约束改变了很多设计决策。低核数环境和 4 核以上的区别不是"慢几倍"，而是：

- **没有并行度可借**。所有优化只能是"少干活"，不能是"多核分摊"。
- **GC 成为主要 CPU 消耗**。Go 的 GC 是并发的，核少时它和业务抢同一个核。分配越少，GC 越少，吞吐越高。**所以"零分配"在低配下不是洁癖，是性能策略的核心。**
- **内存上限是硬的**。2 GiB 的机器上通常还跑着别的服务（Web 服务、数据库），donothack 自己不该超过 120 MiB（`small` 档 48 MiB）。
- **慢速攻击会直接打爆内存**。每个连接都有自己的读缓冲、写缓冲、事务对象，连接数不设上限，攻击者用几千个半开的连接就能把 VPS 打挂。

---

## 1. 性能分级（profile）

三档 profile，启动时按 cgroup 自动探测，可显式覆盖（`profile: small|medium|large|auto`）。

**目标机型是 `medium`（2 vCPU / 2 GiB）；`small`（1 vCPU / 512 MiB）是必须保证能跑的最低线，不是主目标。**

| 项 | `small` | `medium`（**目标档**） | `large` |
| --- | --- | --- | --- |
| 目标机器 | 1 vCPU / 512 MiB–1 GiB | 2 vCPU / 2 GiB | 4+ vCPU / 8 GiB+ |
| 空载常驻内存目标 | < 15 MiB | < 25 MiB | < 80 MiB |
| 满负载内存目标 | < 48 MiB | < 120 MiB | < 600 MiB |
| 硬内存上限（GOMEMLIMIT） | 容器内存 × 50% | × 50% | × 70% |
| GOGC | 200 | 200 | 100 |
| 请求体检查上限 | 128 KiB | 512 KiB | 1 MiB |
| HTTP/2 与 h2c | 默认关 | 默认关（明文站用不上；启用 TLS 时可开） | 默认开 |
| 最大并发连接 | 256 | 1024 | 4096 |
| 上游空闲连接/主机 | 16 | 64 | 256 |
| 规则集条数上限 | 400 | 2000 | 10000 |
| 预筛字面量上限 | 20000 | 60000 | 200000 |
| 命中事件 ring buffer | 256 | 1024 | 4096 |
| 控制台额外内存预算 | ≤ 8 MiB | ≤ 24 MiB | ≤ 64 MiB |
| 控制台事件查询范围上限 | 24h / 扫最近 3 天 | 同左 | 同左 |
| 限速状态表容量上限 | 8192 key | 65536 key | 262144 key |
| 审计日志输出 | stdout（交 journald） | 文件 + 轮转 | 文件 + 轮转 |
| TLS 终止 | 可选，默认关 | 可选，默认关 | 可选 |

**没有"响应体检查上限"这一项**：本轮不做响应侧检测，响应完全不进内存，直接流式透传（见 `docs/DESIGN.md` §12）。这是砍范围带来的最大性能收益。

**自动探测**：读 cgroup v2 `memory.max` / `cpu.max`，退化到 cgroup v1，再退化到 `/proc/meminfo` + `runtime.NumCPU()`。探测结果写进启动日志与 `/readyz` 详情，方便排查"为什么规则没生效"（小档会拒载超限规则集）。探测不到时按 `medium` 处理。

---

## 2. 性能目标（量化，可验收）

以下为**目标值**，需要在目标机器上实测确认后才算达成。未经实测的数字不作为承诺。

### 2.1 `medium` profile（2 vCPU / 2 GiB，**目标档**）

| 场景 | 目标 |
| --- | --- |
| 纯转发，GET 无 body，无规则命中 | 附加延迟 P50 < 0.15ms，P99 < 0.5ms |
| 1 KiB body + 全规则评估，无命中 | 附加延迟 P99 < 1.5ms |
| 命中拦截（不转发上游） | P99 < 1ms |
| 吞吐（1 KiB GET，keep-alive，2 核） | ≥ 8000 rps |
| **相对裸反向代理**的吞吐降幅 | < 10% |
| 相对直连上游的吞吐降幅 | 仅记录作参考，**不作为门禁** |

> **为什么基线必须是"裸反向代理"而不是"直连上游"：**
> 直连是一跳 HTTP，经过 WAF 是两跳。同一台机器上两跳的吞吐天然接近腰斩 ——
> 拿直连当基线，量到的是"多了一跳代理"，不是"WAF 慢"。
> 因此 `scripts/bench.py` 会跑三次：直连（参考）、`cmd/plainproxy` 裸代理（公平基线）、
> donothack。**开门禁的只有最后一个对比。**
> 本机实测印证了这一点：medium 档下直连 84000 rps、裸代理 26000 rps、
> donothack 29000 rps —— 相对直连掉 66%，但相对裸代理是 -10%（即更快）。
> 那不是"我们比裸代理快"，是 P0 还没有检测逻辑，差值落在测量噪声里。
| 空载常驻内存 | < 25 MiB |
| 满负载内存 | < 120 MiB |
| 压测 30 分钟后 RSS | 稳定，无单调增长 |
| reload 期间 | 零失败请求、零连接中断 |

### 2.1b `small` 保底线（1 vCPU / 512 MiB）

不是主目标，但**必须能跑**：≥ 3000 rps、满负载 < 48 MiB、空载 < 15 MiB、纯转发 P99 < 0.5ms。达不到就是缺陷，不是"低配就该这样"。

### 2.2 每请求 CPU 预算（`medium`：2 vCPU @ 3GHz，8000 rps ⇒ 每请求约 250µs 单核等效预算）

donothack 自身应控制在 **100µs 以内**，其余留给业务与内核：

| 环节 | 预算 |
| --- | --- |
| 连接与协议处理（net/http） | 25µs |
| 解析与归一化 | 20µs |
| 全规则评估（含变换链与预筛） | 40µs |
| 决策与审计编码 | 10µs |
| 代理与上游转发 | 15µs |

超预算的环节用 pprof 定位，不允许"大概慢一点没关系"。

### 2.3 内存预算（`medium`：2 GiB 机器）

```
规则集（2000 条 + AC 自动机）       ≤ 24 MiB
预筛自动机                          ≤ 12 MiB
并发连接 1024 × 每连接 16 KiB       ≤ 16 MiB
事务对象池 + 缓冲池                  ≤ 8 MiB
限速/封禁状态表 65536 key           ≤ 6 MiB
命中 ring buffer 1024 条            ≤ 4 MiB
审计输出缓冲                        ≤ 2 MiB
Web 控制台（聚合桶 + 会话 + 静态缓存）≤ 24 MiB
Go 运行时自身 + 栈                  ≤ 16 MiB
────────────────────────────────────────────
合计                                ≤ 112 MiB
合计目标（留余量）                   ≤ 120 MiB
```

控制台那一项是**上限不是常态**：分钟聚合桶定长约 100KB，ring buffer 与静态缓存合计通常 4–8 MiB。但上限必须按 24 MiB 预留，否则"平时 8 MiB，某次查询涨到 40 MiB"就会把整机拖下水。

`small` 档同上按 1/4 规模缩放，目标 48 MiB。

**硬约束**：`并发连接上限 × 每连接内存预算 + 规则集 + 池` 必须小于可用内存的 60%，否则启动时拒绝并报错，不要等跑起来再 OOM。

---

## 3. 热路径零分配（低配下的核心策略）

### 3.1 硬指标

- `BenchmarkEngine_NoMatch`（预热后）：**0 allocs/op**。
- 端到端热路径（GET 无 body、无命中）donothack 自身新增分配：**≤ 2 allocs/req**（不含 `net/http` 内部）。
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
- 池命中率进指标（`donothack_pool_hits_total`），命中率低于 90% 说明对象在别处被持有，要查。

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
| 响应体 | 完全不读入内存 | 流式透传（本轮不做响应检测） |
| 并发连接 | profile 值 | 信号量满则 503（可配直接断连） |
| 单连接读缓冲 | 32 KiB（含头） | net/http 层限制 |
| 限速/封禁状态表 | profile 值 key 数 | LRU 淘汰最旧 |
| 命中 ring buffer | profile 值条数 | 覆盖最旧 |
| 审计队列 | 4096 条 | 丢弃并计数（**绝不阻塞请求**） |
| 审计日志落盘速率 | **实测约 22 MB/s @ 29k rps**（见下） | 三道上限自动轮转与清理 + `log.access_mode` 采样 |
| 规则集条数 | profile 值 | 启动/reload 直接拒绝 |
| 预筛字面量 | profile 值 | 超出部分不进自动机 + 告警 |
| 参数个数 | 默认 1000 | 超出不解析，记 `PROTO` 分 |
| 单参数值长度 | 默认 64 KiB | 截断参与检测 |
| JSON 深度 / 节点数 | 32 / 10000 | 停止展开 |
| 解码迭代次数 | 8 层 | 停止并记 `PROTO` 分 |
| 解压输出 | min(声明, 检查上限 × 4) | 停止并记 `PROTO` 分 |
| 单请求总时限 | profile 值（`medium` 15s） | 中断 |
| 控制台查询时间范围 | 24h（可配），只扫最近 3 天文件 | 超出要求导出 |
| 控制台查询单页行数 | 200 | 服务端截断 |
| 控制台查询超时 | 3s | 返回部分结果并标注 |
| 控制台额外内存 | profile 值（`medium` 24 MiB） | 超限告警；静态资源缓存停止增长 |

**限速状态表必须有容量上限**：否则攻击者伪造源 IP 喷洒，把内存打爆。这一点和"必须有界"是同一个道理。

**审计日志的落盘速率也必须当成资源来管** —— 这一条是压测逼出来的。P0 实测：
29k rps ＋ 每请求一条访问日志 ≈ **22 MB/s**，8 秒压测写出 176 MB。
照这个速率，一台 20 GB 磁盘的 VPS 十几分钟就被日志写满，而写满之后的表现是
"WAF 静默失能"——最糟的失败模式。

因此日志模块有四道闸，**P0 已实现前三道**：

1. **单文件上限** `log.max_size_mb`：到量就归档。
2. **保留份数** `log.max_backups` + **目录总配额** `log.total_max_mb`：超了删最旧的。
   两份上限都要有 —— `max_backups` 管份数，`total_max_mb` 管"份数 × 大小相乘之后仍可能失控"。
   总配额是硬顶：`max_backups: 20 × max_size_mb: 100` 隐含 2 GB，而 `total_max_mb: 512` 会先把它削到约 5 份。
   **实测**：1 MiB 单文件 + 3 MiB 总配额，6 秒 16.4 万请求 → 47 次轮转、**删除 62 个旧文件**、
   目录稳定在 2.26 MiB。清理在启动时也跑一次（只靠"轮转时清理"的话，长期不轮转的进程会一直堆垃圾）。
3. **磁盘水位** `log.min_free_mb`（默认 1 GiB）：磁盘剩余低于它就**丢弃日志并计数**，绝不再写。
   日志的价值远低于业务可用性 —— 磁盘被日志写满会连带拖死业务与系统服务，宁可丢日志。
4. **`log.access_mode`**：`all` / `hit`（只记非 pass）/ `sample`（非 pass 全记 + pass 按比例采样）。
   默认 `all` —— P0/P1 还没有检测能力，"只记非 pass"等于什么都不记。
   **上到 block 模式后应改为 `hit`**：审计日志要留的是"被拦了什么"，不是"有多少正常请求通过"。

轮转后 gzip 旧文件（异步单 worker，压不过来就跳过、绝不阻塞写）：实测 1 MiB 文本日志压到 51 KB。

被丢弃、被删除的日志条数都在 `/readyz` 的 `log` 字段里 —— **这两件事必须能被看到**，
否则出问题时只剩下"日志怎么少了一段"这种无法解释的现象。

P4 补齐：有界异步队列（队列满丢弃并计数）、落盘速率进指标（`donothack_audit_bytes_total`）。

### 5.3 reload 的内存峰值

reload 时新旧规则集共存，峰值内存 = 2 × 规则集 + 2 × 预筛自动机。`small` 档规则集上限 400 条，峰值约 24 MiB；`medium` 档 2000 条约 72 MiB。启动时按此校验并打印预算表。

---

## 6. 连接、超时与协议层

| 参数 | `small` | `medium` | 说明 |
| --- | --- | --- | --- |
| `MaxHeaderBytes` | 32 KiB | 32 KiB | net/http 默认 1 MiB，低配下太大，是内存放大点 |
| `ReadHeaderTimeout` | 5s | 5s | 防 slowloris |
| `ReadTimeout` | 15s | 15s | 含 body |
| `WriteTimeout` | 30s | 30s | |
| `IdleTimeout` | 60s | 60s | keep-alive 复用，别太长占内存 |
| 最大并发连接 | 256 | 1024 | 信号量 |
| 上游 `MaxIdleConnsPerHost` | 16 | 64 | |
| 上游 `IdleConnTimeout` | 30s | 30s | |
| `TCP_NODELAY` | 开 | 开 | 禁用 Nagle，降低小响应延迟 |

**响应零缓冲**：不做响应侧检测，响应直接流式透传，不需要 body tee，也不需要在内存里留副本。

**保留零拷贝快路径**：请求体透传（超过检查上限、或 `Content-Type` 为二进制而未进检测的大 body）与响应转发时，不要包一层会把 `ReadFrom`/`WriteTo` 吃掉的自定义 reader —— Go 在 Linux 上对 `net.TCPConn` 有 splice 快路径，包错一层就从 splice 退化成用户态拷贝。

---

## 7. 构建与部署参数

### 7.1 构建

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
  go build -trimpath -ldflags="-s -w -X donothack/internal/version.Version=$VER" \
  -o dist/donothack-linux-amd64 ./cmd/donothack
```

- **`GOAMD64=v1` 必须是 v1。** 低配 VPS 的 CPU 经常是老型号，`v3` 需要 AVX2，跑起来直接 `illegal instruction` 崩掉。默认值就是 v1，但要在 Makefile 里显式钉死，防止有人手滑。
- 同时产出 `linux/arm64`（Oracle/Ampere 免费机型常见），成本为零。
- 目标二进制 ≤ 14 MiB（strip 后；比原定 12 MiB 多出的部分给 Web 控制台的前端资源，约 200 KB 未压缩 / 60 KB gzip，其余是余量）。依赖只有标准库 + `yaml.v3`。
- **不用 UPX**：会破坏 `-trimpath` 的可调试性，某些 VPS 的杀软还会误报。要做成可选开关，默认关。

### 7.2 systemd 单元模板（随仓库提供）

```ini
[Service]
ExecStart=/usr/local/bin/donothack -c /etc/donothack/config.yaml
Restart=always
RestartSec=1
LimitNOFILE=8192
MemoryMax=768M          # medium 档硬顶（2 GiB 机器留一半给业务）
                        # small 档（512 MiB 机器）改成 384M
CPUQuota=90%
OOMScoreAdjust=200      # 宁可先杀 donothack，也别让业务跟着倒霉
StandardOutput=journal
StandardError=journal
# 不用自写文件轮转：journald 更省 CPU 与磁盘
```

要点：`MemoryMax` 给 donothack 一个硬天花板，配合 `GOMEMLIMIT`（软）形成双保险 —— 软限让 Go 自己 GC，硬限是最后一道。`OOMScoreAdjust` 是关键：整机内存紧张时优先杀 donothack，保证业务活着。这符合"WAF 不能成为单点故障"的原则。**注意 `MemoryMax` 要留出余量**：`medium` 档满负载目标 120 MiB，但 reload 峰值与突发流量会上去，768M 是天花板不是目标。

### 7.3 Docker

```bash
# medium 档
docker run -d --memory=768m --cpus=2 --ulimit nofile=8192 -p 80:8080 donothack
# small 档
docker run -d --memory=384m --cpus=1 --ulimit nofile=8192 -p 80:8080 donothack
```

镜像用 `scratch` 或 `gcr.io/distroless/static`，不带 shell、不带包管理器，镜像 < 20 MiB。

---

## 8. 降级策略（过载保护）

低配机器最怕的不是"慢"，是**雪崩**：WAF 抢光 CPU → 业务超时 → 重试 → WAF 更忙。

降级必须**分级、可见、可配**：

| 级别 | 触发条件 | 动作 | 检测能力损失 |
| --- | --- | --- | --- |
| L0 正常 | — | 全功能 | 无 |
| L1 丢日志 | 审计队列满 | 丢弃日志并计数（已有设计） | 无（只丢证据） |
| L2 降检测深度 | 请求处理延迟 P99 > 50ms 持续 10s | 跳过昂贵算子（`detectSQLi`/`detectXSS`/复杂正则），只跑预筛与廉价算子 | 有，明显 |
| L3 只跑阶段 1 | 持续 30s 未恢复 | 停请求体解析与阶段 2，只跑扫描器/协议规则 | 有，严重 |
| L4 旁路 | 持续 60s 未恢复 | 纯转发，只记录，不检测 | 完全丧失 |

**硬性约束**：

- 降级状态必须体现在三处：结构化日志（`level=alert`）、指标（`donothack_degraded_level`）、`/readyz` 详情。**静默降级等同于 WAF 悄悄失效，不可接受。**
- **`block` 模式下只允许 L1。** L2 及以上一律拒绝，过载时返回 503 —— 选择 block 模式意味着部署方把安全放在可用性之前，此时降检测或放行都是背叛预期。拒绝服务比放行攻击更符合这个选择。
- `detect` 模式可自动降级到 L4（反正本来就不拦，降级只是省资源）。
- 配置项 `engine.degrade: auto | off`，默认 `auto`。
- 每次降级/恢复都写审计，`/admin/events` 可查。

---

## 9. 明确取舍

诚实列出放弃了什么，避免误以为"什么都能要"：

| 放弃 | 原因 | 影响 |
| --- | --- | --- |
| **响应侧检测（整块）** | 需求只要求识别请求侧的 payload；一旦要做就得缓冲响应体，内存与 CPU 成本都要重算 | 无法发现"攻击成功后的数据外带与报错回显"；换来响应零缓冲的延迟与内存收益 |
| HTTP/2 与 h2c | 明文站用不上；每流状态开销也不小 | 默认只支持 HTTP/1.1（含 keep-alive）；启用 TLS 时可开 |
| PCRE / 完整 ModSecurity 语义 | 需 CGO 或庞大解释器 | SecRules 兼容层只做子集（见 RULES.md §11） |
| 超长值尾部深检测 | 变换链与扫描有长度上限 | > 8 KiB 的值只扫前 8 KiB，尾部靠廉价算子 |
| payload 全量留存 | 内存与磁盘都不可接受 | 只有 ring buffer 摘要，需要取证时开 `capture_payload` |
| 多上游编排 / 服务发现 | 增加复杂度与内存 | 单上游 |
| 分布式限速协同 | 需 Redis 常驻连接与内存 | 单机内存限速 |

### 什么情况下这台机器不该跑 donothack

- 内存 < 512 MiB：Go 运行时 + 规则集 + 连接缓冲自己就吃掉大半，剩给业务的太少。
- 1 vCPU 但是严重超售的共享核：附加延迟会从 0.5ms 涨到几毫秒，量级不对。
- 上游是静态站点或有 CDN 兜底：此时 donothack 的收益低于它的延迟成本，应把 WAF 放到 CDN 边缘。

遇到这些情况，方案是前置 CDN 或升级 VPS，不是把 donothack 的参数调到极限硬塞。

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
BenchmarkProxyPassthrough      ≤ 2 allocs/op（donothack 自身）
```

### 10.2 端到端

`scripts/bench.py`（Python，跨平台；不依赖 hey / wrk / psutil）：

1. 编译 `cmd/donothack`、`cmd/loadgen`、`cmd/testupstream`、`cmd/plainproxy`。
2. 起 `testupstream`（固定 200 + 1 KiB body）作为假上游。
3. 压**直连上游** → 参考值。
4. 起 `cmd/plainproxy`（同样的反向代理与 Transport 调优，但**不做检测**）→ **公平基线**。
5. 起 donothack（指定 profile），压它。
6. 采集 RPS、P50/P90/P99、donothack RSS（Windows 用 `tasklist`，Linux 读 `/proc/<pid>/status`）。
7. 输出三列对比与 **WAF 开销**（donothack 相对裸代理），报告写入 `docs/bench/<时间戳>-<profile>.md`。

`cmd/loadgen` 是自带的压测器（只用标准库）——低配机器上装不了 hey / wrk 时，
交叉编译一个丢过去就能出数。

**报告进版本库，原始数据不进**（`.gitignore` 已排除）。

### 10.2b 透传保真度（功能门禁，P1 起每次必跑）

`scripts/passthrough.py`：把同一批请求分别打"直连上游"与"经过 donothack"，
逐项比对状态码、响应体长度、响应体哈希、Content-Type 与响应头。

WAF 是透明代理，**任何**对上游语义的改动都是 bug（路径被重新编码、Content-Length 变了、
响应头丢了一个）。这个脚本把这类回归变成一次可重复的检查。也可以直接拿真实站点当上游：

```
python scripts/passthrough.py --direct http://127.0.0.1:8787 --waf http://127.0.0.1:18080
```

### 10.3 受限环境模拟

没有目标 VPS 时，先在本机模拟出主要约束：

```powershell
# Windows：限制到 2 个 P、48 MiB 软内存上限（模拟 small）
$env:GOMAXPROCS=1; $env:GOMEMLIMIT=48MiB
# 模拟 medium 的目标档
$env:GOMAXPROCS=2; $env:GOMEMLIMIT=160MiB
```

```bash
# Linux：cgroup 精确限制（small）
systemd-run --scope -p MemoryMax=384M -p MemoryHigh=320M -p CPUQuota=100% \
  ./dist/donothack -c bench/config-small.yaml
# medium
systemd-run --scope -p MemoryMax=1280M -p MemoryHigh=1024M -p CPUQuota=200% \
  ./dist/donothack -c bench/config-medium.yaml
```

**诚实说明**：`GOMAXPROCS` 能模拟核数下的调度行为，`GOMEMLIMIT` 能模拟内存压力，但**模拟不出真实 VPS 的 CPU 型号、磁盘 IO 与网络栈**。最终数字必须在真机（2 核 2 GiB）上跑一次才算数，跑法：

```bash
curl -sSL <仓库>/scripts/bench.py | bash -s -- --profile medium --duration 60
```

结果贴回仓库 `docs/bench/`，作为该 profile 的基线。

### 10.4 剖析（优化时用）

- `net/http/pprof` 挂在管理端口（`127.0.0.1:9091/debug/pprof/`），**不暴露到公网**，默认关，`admin.pprof: true` 才开。
- 定位顺序：先看 `allocs`（`-benchmem`），再看 `pprof -alloc_space`，最后才看 `cpu`。低核数下 80% 的问题出在分配，不是算法。
- GC 调优前先跑 `GODEBUG=gctrace=1`，确认 GC 频率与暂停时间，别凭感觉调 `GOGC`。

---

## 11. 待确认

已定（2026-10-06 评审）：

- [x] 目标机型：**2 vCPU / 2 GiB（`medium` 为目标档）**，1 vCPU / 512 MiB（`small`）为保底线
- [x] 检测范围：只做请求侧，不做响应检测（因此没有响应缓冲开销）
- [x] TLS：默认关，明文 HTTP 与 HTTPS 都要支持
- [x] 产品与二进制名：`donothack`

仍待确认：

- [ ] 审计日志 `small` 档默认走 stdout 交 journald（不自写文件轮转）是否接受 —— 这需要机器上有 systemd。
- [ ] 降级策略：默认 `auto`、`block` 模式只允许 L1（L2+ 拒绝并返回 503），是否认可。
- [ ] 是否提供真机（2 核 2 GiB）跑一次基线测量 —— 没有的话，第 2 节的目标值只能标记为"未经实测"。
- [ ] 是否保留限速/封禁模块（需求只提了 payload 识别，限速属附加能力，成本低但也不是必需）。

---

## 附录 P6：性能门禁实测与三个被抓出来的真问题

### 门禁实测（2026-10-06，本机 24 核 / 16 GiB，medium 档，32 并发 / 10s）

| 指标 | 直连（参考） | **裸代理（公平基线）** | donothack | 结论 |
| --- | --- | --- | --- | --- |
| RPS | 89616 | 27429 | **35332** | 相对基线 **-28.8%**（更快）→ 门禁「< 10% 开销」达标 |
| P99 | 1.580ms | 3.225ms | **2.288ms** | 优于基线 |
| RSS | — | — | **44.2 MiB** | 门禁 ≤ 120 MiB 达标 |
| 非 2xx / 错误 | 0 | 0 | 0 | 无 |

绝对目标 ≥ 8000 rps 达标。直连那一列只是参考（多一跳的成本，不是 WAF 的慢）。
报告：`docs/bench/20261006-212617-medium.md`。

**这些仍是本机数字，不是真机基线** —— 真机（2 vCPU / 2 GiB）那一趟还没跑。

### `BenchmarkEngine_NoMatch`：门禁**未达成**，如实记录

| 指标 | 门禁 | 实测 |
| --- | --- | --- |
| 耗时 | < 20 µs/op | **4.58 µs/op** ✅ |
| 分配 | **0 allocs/op** | **21 allocs/op / 513 B/op** ❌ |

优化过程（每一次都是实测驱动，不是猜）：

| 阶段 | allocs/op | 做了什么 |
| --- | --- | --- |
| 初始 | 98 | 基准此前**根本不存在**；补上后先看清现状 |
| + 无 body 早退 + 池化 parser.Scratch | 27 | 无 body 的 GET 不再白套一层 MultiReader |
| + 变换"无变化即返回入参"（18 个变换） | 21 | 正常业务参数大多不需要任何变换 |

剩余的 21 次分配已定位到三处（`-memprofilerate=1` 精确剖析）：

1. **真正发生变化的变换输出**（~4 次）：UA 里有大写字母，`lowercase` 必须产出新缓冲。
   消除方案：变换签名改成带 dst（`func(dst, in []byte, ...) []byte`），
   输出写进每请求复用的 arena。**这是最大的一块，也是唯一需要动 30 个变换的一个。**
2. **预筛的集合迭代闭包**（~2 次）：`expandCollection` 的回调捕获局部变量后逃逸。
   消除方案：与 `evalRuleSingle` 一样改成按下标直接迭代（那里已经改完，省下 6 次）。
3. **规范化路径的字符串**（1 次）：`string(normalized)`。
   消除方案：事务内置一个 512 字节的内联缓冲，超长才回退堆分配。

> 判断：当前分配率（513 B/op × 35k rps ≈ 18 MB/s）配合 GOGC=200 与 GOMEMLIMIT
> 不构成 GC 风险（实测吞吐反而高于裸代理），所以**这一项不阻塞投产**；
> 但门禁就是门禁，未达成要写清楚，方案也写清楚。

### 三个被抓出来的真问题（都属于"不真跑就发现不了"）

#### 1. 降级器把**正常负载**判成过载，一路跳到 L4

GC CPU 占比阈值原本定在 L2=0.20 / L4=0.50。但 **Go 的 GC pacer 默认就把 25% 的 CPU
花在 GC 上** —— 0.2 是正常水平，不是压力。压测一上来就跳到 L4。

现在阈值改成 L1=0.35 / L2=0.50 / L3=0.65 / L4=0.80，并把判定抽成可测的 `decideLevel`，
用单测把每一档钉住。

#### 2. 恢复条件写死，导致**一进降级就永远出不来**

原恢复条件要求 `gc_cpu_fraction < 0.10`，而持续负载下 GC 占比长期在 0.15 上下 ——
于是一旦因为某个尖峰进入降级态，实例会**持续 503 直到负载停止**。
现在把"回落"定义成"低于最轻档位的进入阈值"（0.25 上下）。

#### 3. detect 模式的 L4 语义错了：把"旁路"实现成了"拒绝"

`L4` 在文档里的含义是**旁路**（跳过检测，只转发）。但 `ShouldReject()` 在 detect 模式下
对 L4 返回 true → 返回 503。detect 模式本来就只记录、不拦截，"降级"对它意味着少做点检测，
**不是拒绝服务**。现在：

* block / mixed：L2+ 一律 503（不能放未检测的流量过去）；
* detect：**永不 503**，L4 走 `Bypass()` 跳过检测直接转发。

#### 附带：一个"不会失败的基准"

`scripts/bench.py` 把 `-d 8` 传给只认 `8s` 的 `loadgen`，命令直接报错退出，
三轮全部量到 0 RPS —— 而报告照样打印「相对裸代理 < 10%：**达标**（实测 0.0%）」。
现在：`loadgen` 接受裸秒数，`bench.py` 拿到 0 RPS 或解析失败**立刻硬失败**并打印原始输出。
**一个不会失败的基准比没有基准更糟** —— 它会给你一个假的绿灯。

### 门禁达成：`BenchmarkEngine_NoMatch` = **0 allocs/op**

上一节记的是"未达成（21 allocs/op）"。这一节是把它做掉的过程与结果。

| 阶段 | allocs/op | B/op | 做了什么 |
| --- | --- | --- | --- |
| 初始 | 98 | 1988 | 补上基准，先看清现状 |
| 无 body 早退 + 池化 parser.Scratch | 27 | 801 | GET 不再白套 MultiReader |
| 18 个变换加"无变化即返回入参" | 21 | 513 | 正常参数大多不需要变换 |
| AC 加 `ScanBits`（无回调写位图）+ 预筛去闭包 | 11 | 424 | 逃逸闭包不再逐集合分配 |
| `collapseSpaces` / `SplitContentType` 早退 | 7 | 40 | Builder/Split 的无条件分配 |
| **变换链 dst 化 + 双缓冲 arena** | **1** | 16 | 见下 |
| **路径子串复用** | **0** | **0** | 见下 |

现在的实测（本机 24 核，`-benchtime 400ms`）：

```
BenchmarkEngine_NoMatch-24              108640    4294 ns/op      0 B/op    0 allocs/op
BenchmarkEngine_NoMatchManyHeaders-24    51693    9206 ns/op      0 B/op    0 allocs/op
BenchmarkEngine_Hit-24                   42918   12097 ns/op  34792 B/op   17 allocs/op
```

命中路径从 53 allocs / 36 KB 降到 **17 allocs / 34 KB** —— 这条路径本来就允许分配
（要建事件、要记分），但攻击洪泛时它才是内存 churn 的大头，所以一并优化了。

#### 两块最关键的改动

**1. 变换链 dst 化 + 双缓冲 arena。** `Func` 签名加了 `dst`，
变换把结果写进调用方给的缓冲（容量够就零分配）。`EvalScratch` 里放两块缓冲**交替**使用 ——
下一步的输出绝不能覆盖上一步的输入（而它正是下一步的输入）。

两条踩过的坑，都写在代码注释里：

* `region` 取缓冲前必须 `reserve(slot, len(in))` 把容量备够。容量不够时 `append` 会另分配一块，
  那块内存不属于 arena，后面就没法安全复用。
* **只把"确实写在我们缓冲里"的结果存回 arena**（按起始地址判定）。
  变换在"无需改动"时会直接返回入参，而那个入参指向**事务的参数缓冲** ——
  无条件存回会让 arena 引用别人的内存，下一次往 arena 写就把参数覆盖掉。
  这个 bug 的表现是**静默漏检**（预筛看到被改坏的参数值），
  由 base64(JSON) 那条回归测试抓到；如果没有那条"从引擎裁决这一端写"的测试，它会溜过去。

**2. 路径子串复用。** `string(normalized)` 是每请求一次的分配。
但规范化**没有改动**时，路径本来就是 `RequestURI` 的一个子串 —— 直接复用那块字符串即可。
只有真的需要改写（百分号解码、折叠 `//`、去 `..`）才建新字符串。
判定用 `equalStringBytes`（逐字节比较，不分配）。

#### 另外修掉的两处

* `targetMatches(plan, string(key))` 在每个参数上做一次 `string` 转换 → 改成 `[]byte` 版本
  （`equalFoldBytes`），正则目标保留 string 入口（正则本来就要 string）。
* `ev.PayloadBefore = h.Before` 原来是**直接存切片引用**。dst 化之后 `h.After` 指向复用缓冲，
  下一条规则求值就会覆盖它 —— 现在改为显式拷贝。
  顺带说明：即使没有 dst 化，这个写法也依赖"事务 arena 的生命周期恰好覆盖到 record"，
  本身就是脆的。

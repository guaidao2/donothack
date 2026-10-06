# donothack 架构设计

> 状态：待评审（v0 设计稿）
> 目标读者：本项目开发者
> 最后更新：P0 之前

---

## 1. 项目定位

`donothack` 是一个用 Go 编写的、生产环境可用的 Web 应用防火墙，以独立反向代理形态部署在业务服务之前。

一句话：**客户端 → donothack → 上游业务**。核心职责是判断请求头、请求体与参数里有没有攻击 payload，命中则按决策模型放行、记录、拦截、挑战或限速。

### 设计目标

| 目标 | 说明 |
| --- | --- |
| 检测准 | **核心 KPI。** 覆盖 SQLi / XSS / RCE / LFI / webshell / 扫描器等常见 payload，同时误报率可控。范围只做请求侧，见非目标。 |
| 生产可用 | 不是演示品。零停机热加载、优雅停机、健康探针、可观测性、误报可治理，全部是必备项。 |
| 可运维 | **必须有 Web 控制台**（对标雷池）：浏览器里看攻击、查事件、启停规则、加白名单、调限速、改配置、看操作审计。设计与安全要求见 `docs/CONSOLE.md`。 |
| 单二进制 | 纯 Go，无 CGO，`CGO_ENABLED=0` 交叉编译，不依赖 nginx / Apache / Lua / PCRE 动态库。 |
| **低配 VPS 能跑** | **首要约束。** 目标机型 2 vCPU / 2 GiB（`medium` 档），最低支持 1 vCPU / 512 MiB（`small` 档）。预算见 `docs/PERFORMANCE.md`。 |
| 低开销 | 无命中路径附加延迟 P99 < 0.5ms，**相对裸反向代理**吞吐降幅 < 10%。热路径零分配，见 `docs/PERFORMANCE.md` §2.1。 |
| 不成为单点故障 | 任何解析或规则异常都必须 fail-open 放行并留审计，绝不因为 WAF 自身错误导致业务 5xx。 |
| 可对照回滚 | 规则、配置、代码全部进 git，每次决策可追溯到规则 ID 与规则文件版本。 |
| 规则可读可写 | 自研 YAML DSL，安全工程师不需要写 Go 就能加规则；预留 ModSecurity SecRules 兼容层。 |

### 非目标（明确不做）

- **不做响应侧检测**：不检查、不缓冲、不修改响应体与响应头。本轮只判断请求侧 payload。后续若要加（数据泄露、报错回显），按 §12 的保留设计评估，但会重新吃回响应缓冲的内存与延迟成本。
- **不做 DDoS / 流量清洗**：四层洪水交给上游清洗设备或云厂商，donothack 只处理七层语义。
- **不做内容缓存 / CDN**：不缓存响应体。
- **不做多上游负载均衡编排**：P0–P4 只支持单上游（或简单轮询），服务发现留给 P5 之后。
- **不做分布式协同封禁**：单机内存限速为主；多副本只通过 Redis 共享限速与封禁状态，不做全局威胁情报。
- **不自研 TLS 栈**：用标准库 `crypto/tls`。明文 HTTP 与 HTTPS 都要支持，TLS 默认关（很多站点跑 HTTP）。

---

## 2. 术语

| 术语 | 含义 |
| --- | --- |
| Transaction (tx) | 一次请求-响应事务，贯穿流水线的上下文对象 |
| Collection | 变量集合，如 `ARGS`、`REQUEST_HEADERS`、`RESPONSE_BODY` |
| Target | 规则的作用对象，形如 `Collection:selector` |
| Transform | 对变量值的变换函数，如 `lowercase`、`urlDecode` |
| Operator | 匹配算子，如 `regex`、`pm`、`detectSQLi` |
| Phase | 流水线阶段，1 请求头 / 2 请求体 / 3 响应头 / 4 响应体 / 5 收尾 |
| Score | 命中累积分数，按类目计 |
| Verdict | 最终裁决：pass / log / block / challenge / tarpit / drop |
| RuleSet | 编译后的规则全集，不可变，原子替换 |
| Fail-open | 出错时放行（保护业务可用性） |
| Fail-closed | 出错时拦截（保护安全性） |

---

## 3. 总体架构

```
                    ┌──────────────────────────────────────────────────────┐
                    │                     donothack                        │
                    │                                                      │
  Client ─HTTP/TLS─▶│  ┌──────────┐   ┌──────────┐   ┌─────────────────┐  │
                    │  │ realip   │──▶│ listener │──▶│  Transaction    │  │
                    │  │ (XFF)    │   │ (h1/h2)  │   │  (per request)  │  │
                    │  └──────────┘   └──────────┘   └────────┬────────┘  │
                    │                                         │           │
                    │                              ┌──────────▼────────┐  │
                    │                              │  parser / decode  │  │
                    │                              │  归一化 + 变量集合 │  │
                    │                              └──────────┬────────┘  │
                    │                                         │           │
                    │        ┌────────────────────────────────▼───────┐   │
                    │        │            engine (phases)             │   │
                    │        │    P1 headers ──▶ P2 body / args       │   │
                    │        │       └── ruleset (atomic.Pointer)     │   │
                    │        │       └── score accumulator            │   │
                    │        └───────────────┬────────────────────────┘   │
                    │                        │                            │
                    │            ┌───────────▼───────────┐                │
                    │            │       actions         │                │
                    │            │ block/log/tarpit/     │                │
                    │            │ challenge/ratelimit   │                │
                    │            └───────────┬───────────┘                │
                    │                        │                            │
                    │   ┌────────────────────▼─────────────────────┐      │
                    │   │  proxy (RoundTrip, ws tunnel, 响应流式)   │──────┼──▶ Upstream
                    │   └────────────────────┬─────────────────────┘      │
                    │                        │                            │
                    │   ┌────────────────────▼─────────────────────┐      │
                    │   │ audit log / metrics / admin API / alert  │      │
                    │   └──────────────────────────────────────────┘      │
                    └──────────────────────────────────────────────────────┘
```

**检测范围只覆盖请求侧**：请求头、请求体、（含 query / form / JSON / XML / multipart 的）参数。响应侧不缓冲、不检测、不修改，直接流式透传回客户端 —— 这在低配上同时省掉了响应缓冲的内存与延迟，是性能上的一大笔收益。

### 数据流（一次请求）

1. 连接进来，`realip` 按信任链解析真实客户端 IP。**明文 HTTP 站上 `X-Forwarded-For` 是唯一来源，`trusted_proxies` 必须配准**，否则伪造 XFF 即可绕过限速与封禁。
2. 建 `Transaction`，分配 tx id、起始时间。
3. 阶段 1：解析请求行与请求头，装填变量集合，跑阶段 1 规则（扫描器指纹、畸形协议、恶意 UA、异常头）。
4. 阶段 2：按需读取请求体（受 `max_inspect_body` 限制），解压、解码、解析为参数并跑阶段 2 规则（SQLi、XSS、RCE、LFI、webshell）。
5. 决策：若累计分数超入站阈值或命中硬拦截规则，执行动作（默认 403），写审计，结束。
6. 否则转发上游；响应**不缓冲、不检测**，流式透传回客户端。
7. 收尾：写审计日志、更新指标。

---

## 4. 运行模式

| 模式 | 配置 | 行为 |
| --- | --- | --- |
| `detect` | `engine.mode: detect` | 规则照跑、分数照算，但不拦截，只写审计与指标。**上线默认。** |
| `block` | `engine.mode: block` | 超阈值即拦截。 |
| `mixed` | `engine.mode: mixed` | 按类目分别设阈值，例如 SQLi 拦、XSS 只记。 |

模式可热切换，不需要重启。

---

## 5. 核心抽象

### 5.1 Transaction

贯穿一次请求-响应的上下文。所有模块只依赖它，不互相直接调用。

```go
// internal/tx
type Transaction struct {
	ID        string        // 16 字节随机 hex，全链路日志关联用
	StartedAt time.Time
	ClientIP  netip.Addr
	ClientPort int
	Req       *http.Request
	Res       *http.Response   // 上游响应，转发前可能为 nil
	Vars      *Collections
	Score     Score
	Events    []Event          // 命中事件，按时间序
	Verdict   Verdict
	RuleSetVer string          // 命中所用规则集版本，用于复现
	Attrs     map[string]any   // 模块间传递的临时数据（如 challenge 结果）
}
```

### 5.2 Collections（变量集合）

**这是整个 WAF 的关键抽象。** 解析层负责把所有可能的输入来源拆平成一个扁平命名空间，规则只针对命名空间匹配，不关心原始编码与传输格式。所有编码绕过在解析层被统一消化。

```go
// internal/parser
type Collections struct {
	// 请求行
	Method   string
	URI      string   // 原始 URI
	Path     string   // 规范化后的路径
	Query    string   // 原始 query
	Protocol string

	// 参数（同名多值累积）
	ArgsGet  Params   // query string
	ArgsPost Params   // form-urlencoded / multipart 普通字段
	ArgsJSON Params   // JSON body 递归展开，键用点号路径：user.name
	ArgsXML  Params   // XML 文本节点与属性
	Args     Params   // = ArgsGet ∪ ArgsPost ∪ ArgsJSON ∪ ArgsXML（规则默认目标）

	// 其他输入源
	Headers  Params   // 键小写归一
	Cookies  Params
	Files    FileSet  // multipart 文件：字段名、文件名、Content-Type、大小、头部若干字节

	// 请求体原文
	Body       []byte
	BodyTruncated bool  // 超限截断标记，审计要记

	// 响应侧：本轮**不装填**，字段保留以便将来加响应检测时不必改结构
	// （见 §12，以及 §1 非目标）

	// 派生
	RawIP     string
	TxID      string
	TimeStamp string
	UserAgent string
}

type Params map[string][]string

type FileSet map[string]FileMeta

type FileMeta struct {
	FieldName   string
	FileName    string
	ContentType string
	Size        int64
	Magic       string // 前 16 字节，用于 webshell 魔数检测
}
```

**为什么合并 `Args`：** 攻击者控制不了规则用哪个集合。如果规则只查 `ArgsGet`，攻击者把 payload 放进 JSON body 就绕过了。合并集合是防绕过的结构性保证，而不是便利功能。

### 5.3 变量寻址

```go
// internal/rules
type VarTarget struct {
	Collection string  // "ARGS" | "REQUEST_HEADERS" | "FILES" | ...
	Selector   string  // 具体键名；空 = 全部；"/re/" = 正则；"!name" = 排除
	Count      bool    // 只取数量而不取内容（用于 ARGS_COUNT 类检测）
}

type Var struct {
	Target VarTarget
	Key    string   // 实际命中的键，审计要记
	Value  []byte
}
```

解析时把 `VarTarget` 展开为具体的 `Var` 列表，展开结果可缓存进 `Transaction`（同一规则集版本内，同 target 只展开一次）。

---

## 6. 模块划分

模块边界即多人/多 agent 并行开发时的写入边界，禁止跨包直接改别人内部状态。

```
cmd/donothack/              main：命令行解析、装配、信号处理
cmd/donothackctl/           管理客户端（reload、规则自测、状态查询）——可选，P4

internal/config/       配置结构体、YAML 加载、校验、默认值、热加载协调
internal/tx/           Transaction、Collections、Event、Verdict、Score 定义
internal/control/      Snapshot / Apply / Preview / Subscribe —— 控制面唯一写入口
internal/parser/       请求 → Collections（路径规范化、解码链、解压、JSON/XML/multipart）
internal/transform/    变换函数注册表与实现
internal/operator/     算子注册表与实现（regex、pm、detectSQLi、detectXSS、entropy、luhn、ipMatch…）
internal/rules/        规则模型、YAML 加载、编译、索引、RuleSet 与原子替换
internal/engine/       阶段流水线调度、分数累计、决策
internal/actions/      block / log / tarpit / challenge / ratelimit 执行器
internal/ratelimit/    令牌桶与滑动窗口、临时封禁、状态后端接口（memory / redis）
internal/proxy/        反向代理、WebSocket 隧道、响应流式透传（不做 body 缓冲）、连接池
internal/realip/       可信代理链与真实 IP 还原
internal/audit/        结构化审计日志、文件轮转、异步写入
internal/metrics/     Prometheus 指标
internal/admin/        控制面 REST API（/api/v1）、认证、会话、操作审计
internal/console/      Web 控制台静态资源服务（go:embed、CSP、缓存、gzip）
internal/alert/        告警钩子（webhook / 日志标记）
internal/version/      版本、构建信息（ldflags 注入）
web/                   控制台前端源码（原生 ES module SPA，无构建链）
rules/                 内置规则集（YAML）
testdata/              语料（正/负样本）
docs/                  设计文档、规则文档、压测报告
scripts/               压测、语料回归、构建脚本
```

### 依赖方向（只允许自上而下）

```
cmd/donothack
  ├─ config
  ├─ control ──── config / rules / iplist / audit
  ├─ proxy ─┬─ engine ─┬─ rules ─┬─ parser
  │         │          │         ├─ transform
  │         │          │         └─ operator
  │         │          ├─ actions ─ ratelimit
  │         │          └─ tx
  │         ├─ realip
  │         └─ audit / metrics / alert
  └─ admin ─┬─ control            （唯一写入口；API 不直接碰 config/rules）
            ├─ console ── web/    （embed 静态资源）
            └─ metrics / audit
```

`tx` 是最底层，不依赖任何其他内部包。`parser`、`transform`、`operator` 互不依赖。**`admin` 不允许直接改 `config` 或 `rules`，必须经 `control.Apply`** —— 这是控制面与数据面分离在依赖图上的体现。**禁止循环依赖**，用 `go vet` + CI 卡住。

---

## 7. 关键接口

### 7.1 Transform

```go
// internal/transform
type Transform interface {
	Name() string
	Apply(in []byte, params Params) ([]byte, error)
}

// 注册表；规则里写名字，编译期绑定
func Register(name string, fn func(in []byte, p Params) ([]byte, error))
func Lookup(name string) (Transform, bool)
```

约束：**不得原地修改入参**（入参可能是共享的 body 切片），必须返回新切片或明确标注 `InPlace`。buffer 从 `sync.Pool` 取。

### 7.2 Operator

```go
// internal/operator
type Operator interface {
	Name() string
	// Eval 对单个值求值。params 来自规则 YAML 的 operator 参数。
	Eval(ctx *EvalCtx, in []byte, params Params) (Result, error)
}

type Result struct {
	Matched  bool
	Captures []Capture // 命名捕获组，可回填到审计与 tx.Attrs
	Detail   string    // 人类可读的命中说明，进审计
}

type EvalCtx struct {
	Tx     *tx.Transaction
	RuleID string
	Phase  tx.Phase
}
```

算子必须**无状态且并发安全**（编译后的实例被所有请求共享）。有状态的东西（如缓存）必须自带锁或原子。

### 7.3 Action

```go
// internal/actions
type Action interface {
	Name() string
	// Execute 在阶段决策点执行。返回的 Verdict 允许覆盖当前裁决（如 challenge 覆盖 block）。
	Execute(w http.ResponseWriter, tx *tx.Transaction, ev tx.Event) (tx.Verdict, error)
}
```

### 7.4 Engine

```go
// internal/engine
type Engine interface {
	// Phase1 请求行与请求头；可能直接返回终止裁决
	Phase1(ctx context.Context, t *tx.Transaction) (tx.Verdict, error)
	// Phase2 请求体与参数
	Phase2(ctx context.Context, t *tx.Transaction) (tx.Verdict, error)
	// Phase5 收尾：审计与指标。响应侧不做检测，因此没有 Phase3/Phase4。
	Phase5(ctx context.Context, t *tx.Transaction)
}
```

阶段号仍保留 1/2/5，是为了将来若恢复响应侧检测（§12）能直接占用 3/4 而不改动规则语义与 SecRules 兼容映射。

### 7.5 RateLimiter

```go
// internal/ratelimit
type Limiter interface {
	// Allow 返回是否放行、剩余配额、重置时间
	Allow(ctx context.Context, key string, cost int) (ok bool, remaining int, resetAt time.Time)
}

// 状态后端：P3 只实现 memory，接口留出 redis
type Store interface {
	Incr(ctx context.Context, key string, delta int64, window time.Duration) (int64, error)
	Ban(ctx context.Context, key string, ttl time.Duration) error
	IsBanned(ctx context.Context, key string) (bool, time.Duration, error)
}
```

---

## 8. 解析层设计（防绕过的核心）

解析层是 WAF 里最脏、最容易被低估的一层，绕过 90% 发生在这里。

### 8.1 路径规范化步骤（顺序固定，不可调换）

1. 取原始 `RequestURI` 的路径部分，截到 `?` 之前。
2. 去掉 `#` 之后的内容。
3. 单次 URL 解码（`%XX`），非法转义保留原样并记警告（**不要**因为解码失败就丢弃整个请求）。
4. 反斜杠 `\` 归一为 `/`（Windows/IIS 风格绕过）。
5. 去除 `\x00` 及之后的内容（NUL 截断）。
6. 折叠连续 `/`。
7. 解析 `.` 与 `..` 段（RFC 3986 remove_dot_segments）。
8. 截断超过 8 层的冗余 `../` 组合后再次折叠（对抗 `/....//` 与 `%252e%252e` 双重编码，配合解码链）。
9. 长度上限校验（超长 URI 直接按协议违规记分）。

### 8.2 解码链

对**参数值**（不是路径）按规则挂载的解码顺序执行，由规则决定，默认顺序：

```
urlDecode → urlDecode（二次，对抗双写） → htmlEntityDecode →
base64Decode（仅当值符合 base64 形态） → jsDecode → sqlHexDecode →
compressWhitespace → lowercase
```

设计原则：**多解码几层是安全的**，因为解码只让 payload 更"露出来"；而过早 lowercase 会破坏大小写敏感的检测，因此 `lowercase` 放在链尾。

### 8.3 请求体处理

| Content-Type | 处理方式 |
| --- | --- |
| `application/x-www-form-urlencoded` | `url.ParseQuery`，容忍非法编码 |
| `multipart/form-data` | 流式 `multipart.Reader`，字段 → `ArgsPost`，文件 → `Files`（只读前 16 字节魔数 + 元数据，不落盘） |
| `application/json` | 递归展开到叶子，键路径用 `.` 连接；数组用 `[i]`；深度上限 32，节点数上限 10000 |
| `application/xml` / `text/xml` | 文本节点与属性值；**禁用外部实体（XXE）**，`Decoder.Strict = true` 且不注册 Entity |
| 其他 | 只把原文放进 `Body`，供针对 `REQUEST_BODY` 的规则使用 |

解压：`Content-Encoding: gzip | deflate`，解压后大小上限独立于 `maxInspectBody`（默认 4× 上限即停，防解压炸弹），超限标记 `BodyTruncated` 并记分。

### 8.4 边界处理

- 请求体检查上限 `limits.max_inspect_body`，按 profile 取值（`small` 128 KiB / `medium` 512 KiB / `large` 1 MiB）；超限只检查前 N 字节，`BodyTruncated=true` 进审计。**不因为超限就拒绝**（大文件上传是正常业务）。
- 响应**完全不读入内存**，直接流式透传给客户端（本轮不做响应侧检测，见 §12）。`max_inspect_response` 配置项保留但当前不生效。
- `Content-Length` 与实际不符 → 记分（请求走私迹象）。
- 同时出现 `Content-Length` 与 `Transfer-Encoding` → 记分（HTTP 请求走私）。
- 上游连接失败或超时 → 按 `engine.fail_mode` 处理，默认返回 502 并记审计；**不静默降级成"未检测直连"**（那等于凭空绕过 WAF）。

### 8.5 健壮性要求

- 解析层每个入口函数**必须** `defer recover()` 兜底，把 panic 转成"解析失败"事件 + fail-open 放行。
- `parser`、`transform`、`operator` 三个包**必须**有 `go test -fuzz` 语料，进 CI。
- 任何解析失败都进审计（`event: parse_error`），不允许静默吞掉。

---

## 9. 规则引擎设计

### 9.1 加载 → 编译 → 替换

```
rules/*.yaml ──load──▶ []Rule ──validate──▶ []Rule ──compile──▶ RuleSet ──atomic swap──▶ engine
                                    │                                  │
                                    └─ 失败：报错 + 保留旧 RuleSet      └─ 编译期预筛索引
```

**编译期做的事**（全部为了运行期少干活）：

1. **目标展开表**：把每个 `VarTarget` 编译成快速查询计划（精确键用 map，正则键用预编译 `*regexp.Regexp`）。
2. **变换链去重**：把全部规则的 `transforms` 链归一化去重，得到"不同链集合"（实践中 300 条规则只有 5~10 条）。运行期每个不同链只算一次，其输出各做一次扫描。
3. **共享字面量预筛**：对算子的模式提取最长字面量子串（如 `regex: "(?i)union\s+select"` → `union`），全部规则汇入**同一个** Aho-Corasick 自动机，终态映射到规则位图。请求进来先用 AC 扫描拿到"可能命中的规则集合"，再只对候选跑昂贵算子（复杂正则、libinjection）。无字面量的规则（`entropy`、`validateByteRange`、`luhn`）归入廉价算子组直接执行。**这是低配下性能的主要来源，详见 `docs/PERFORMANCE.md` §4。**
4. **短路标记**：标记 `severity: critical` + `action: block` 的规则为 hard-block，命中即终止本阶段剩余规则。

### 9.2 RuleSet 与热替换

```go
// internal/rules
type RuleSet struct {
	Version   string            // 内容哈希，审计与复现用
	LoadedAt  time.Time
	ByPhase   [6][]*CompiledRule
	prefilter [6]*ahocorasick.Matcher
	byID      map[string]*CompiledRule
	exceptions *ExceptionSet    // 白名单/例外
}

// engine 持有；替换无锁
var current atomic.Pointer[rules.RuleSet]

func Swap(rs *rules.RuleSet) (old *RuleSet)
```

编译出的 `RuleSet` **完全不可变**，运行期只读。因此在途请求不会看到半成品规则集。

### 9.3 规则定位与报错

每条 `Rule` 记录来源文件与行号。编译失败时报错形如：

```
rules/sqli.yaml:42: unknown transform "urldecodee" (did you mean "urlDecode"?)
```

编译失败**整批拒绝**，不做部分加载（避免出现"以为加载了 500 条其实只有 300 条"的隐性缺口）。

### 9.4 例外与白名单

```yaml
exceptions:
  - id: allow-admin-api
    match:
      paths: ["/admin/api/*"]        # glob
      source_ips: ["10.0.0.0/8"]
    disable_rules: ["*"]             # 该路径完全不过规则
    reason: "内部管理接口，业务需要传原始 SQL 片段"
    expires: 2026-12-31              # 过期自动失效，强制复审
```

要求：例外必须带 `reason` 和 `expires`，到期后加载器告警。防止"临时加的例外变成永久后门"。

---

## 10. 决策模型

### 10.1 评分制

不用"一条规则命中就拦"的硬规则（那会 403 掉带单引号的正常评论）。按**类目**累积分：

```yaml
scoring:
  inbound_anomaly_threshold: 5     # 入站累计达到 5 分 → 拦
  # outbound_anomaly_threshold 保留配置位但不生效（本轮不做响应侧检测，见 §12）
  categories:
    sqli:     5
    xss:      5
    rce:      5
    lfi:      5
    rfi:      5
    webshell: 5
    scanner:  3
    protocol: 5
    upload:   3
    # leakage（响应侧泄露）保留但不生效，见 §12
```

规则声明自己属于哪个类目，命中时加该分。这样单条弱规则（扫描器 UA）不会直接封站，而 SQLi 命中一条就够拦。

### 10.2 裁决

```go
type Verdict int

const (
	VerdictPass      Verdict = iota // 放行
	VerdictLog                      // 记录但放行
	VerdictBlock                    // 拦截
	VerdictChallenge                // JS Cookie 挑战
	VerdictTarpit                   // 慢速响应（拖住自动化工具）
	VerdictDrop                     // 直接断连，不回响应
)
```

裁决优先级（高覆盖低）：`Drop > Block > Tarpit > Challenge > Log > Pass`。

动作按严重度映射：

| 分数区间 | detect 模式 | block 模式 |
| --- | --- | --- |
| < threshold | pass | pass |
| ≥ threshold | log | block（403，可配重定向或自定义页） |
| 命中 scanner 类 | log | challenge（先出 JS 挑战，过关放行，减少正常爬虫误伤） |
| 命中 sqli/rce 且 urgent | log | block + 临时封禁 IP 5 分钟 |

### 10.3 拦截响应

默认 `403` + 纯文本最小响应体（不回显匹配到的 payload，防止反射型利用与信息泄露）。可配置：

- 自定义错误页（路径）
- 重定向到指定 URL
- 返回 `444`（nginx 风格，直接断连）
- 附带 `X-Request-ID`（与审计日志关联，便于用户报障时定位）
- `Retry-After`（配合限速）

---

## 11. 限速与封禁

三个层次，配置独立：

1. **连接/请求速率**：按 `IP` 维度令牌桶，默认 100 rps 突发 200。
2. **规则维度**：同一 IP 在时间窗内命中同一规则 N 次后升级为封禁（fail2ban 风格）。默认 60 秒内命中 20 次 → 封 300 秒。
3. **敏感路径维度**：`/admin`、`/.git`、`/.env` 等路径命中即计数，不设阈值直接记分（这类路径正常业务永不访问）。

要点：

- 限速 key 支持组合：`ip`、`ip+path`、`ip+method`、`header:X-API-Key`。
- **真实 IP 还原必须先做对**，否则伪造 `X-Forwarded-For` 就能绕过限速。信任链配置见 §13。
- 白名单 IP/CIDR 直接跳过限速（配置里显式列出）。
- 封禁状态默认内存（`TTL` map + 定期清理）；多副本用 Redis 后端，接口在 P3 就固定。

---

## 12. 响应侧检测（**本轮不做**，保留设计）

**范围决定：本轮只判断请求头、请求体与参数里有没有攻击 payload，响应侧不检测、不缓冲、不修改。** 理由是需求明确收窄，而且不做响应缓冲在低配机器上省下的是实打实的内存与延迟。

以下内容作为**将来若要加回来**的设计备忘保留：

- 目的不是拦攻击者，而是阻止利用成功后的数据外带与回显。
- 敏感数据泄露：身份证、银行卡（Luhn 校验）、手机号、私钥（`-----BEGIN ... PRIVATE KEY-----`）、云厂商 AK/SK 形态、JWT。
- 报错回显：`SQL syntax`、`ORA-`、`Warning: mysql_`、Go panic 栈、Java 堆栈。
- Webshell 特征：响应体含 `eval(`、`base64_decode(` 且请求侧有可疑参数。
- 响应头安全校验（可选，记分不拦）：缺 `X-Content-Type-Options`、缺 `Content-Security-Policy`、`Server` 头版本泄露。

**代价要先说清**：一旦恢复响应体检测，就必须缓冲响应体（流式响应只能缓冲前 N 字节再放行），CPU 与内存预算都要重算，`small` 档基本承受不住。所以这件事要做就得单独评估，不能顺手加。

代码结构上已经留好位置：`Engine` 保留阶段号 3/4（§7.4），`Collections` 保留响应字段（§5.2），规则 DSL 保留 `RESPONSE_*` 集合（`docs/RULES.md` §5.1），但都标记为未实现。

---

## 13. 配置系统

### 13.1 配置结构

```go
// internal/config
type Config struct {
	Profile   string          `yaml:"profile"`  // small | medium | large | auto（按 cgroup 探测；探测不到取 medium）
	Listen    ListenConfig    `yaml:"listen"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	TLS       TLSConfig       `yaml:"tls"`
	RealIP    RealIPConfig    `yaml:"real_ip"`
	Engine    EngineConfig    `yaml:"engine"`
	Rules     RulesConfig     `yaml:"rules"`
	Limits    LimitsConfig    `yaml:"limits"`
	Log       LogConfig       `yaml:"log"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Admin     AdminConfig     `yaml:"admin"`
	Alert     AlertConfig     `yaml:"alert"`
}

type RealIPConfig struct {
	// 只有来自这些 CIDR 的对端才被信任其 XFF/X-Real-IP 头
	TrustedProxies []string `yaml:"trusted_proxies"`
	// 从右往左剥离可信代理，取第一个不可信的地址
	Header         string   `yaml:"header"`          // X-Forwarded-For
	Recursive      bool     `yaml:"recursive"`       // true=剥离全部可信代理
}
```

`trusted_proxies` 为空时，**忽略所有 XFF**，直接用连接对端地址。这是安全默认值。

**明文 HTTP 场景要特别注意**：站点跑 HTTP 时（本项目的常见场景），如果前面有 nginx 或 CDN，`trusted_proxies` 必须填对，否则限速与封禁的 key 会退化成代理 IP（全员共享一个桶），或者被伪造 XFF 直接绕过。启动时若 `trusted_proxies` 为空但检测到请求带 `X-Forwarded-For`，打一次 `level=warn`。

### 13.2 热加载

热加载是 `control.Apply` 的一个 `Mutation` 实现（见 `docs/CONSOLE.md` §2）。触发方式：SIGHUP、`POST /api/v1/config/reload`、或控制台点"保存"。**三条路走的是同一段代码**，不允许各写一套。

```go
// 监听 SIGHUP 或 POST /api/v1/config/reload；控制台保存也走这里
func (m *Manager) Reload(ctx context.Context, path string) (*control.Snapshot, error) {
	return m.ctrl.Apply(ctx, configMutation{path: path})
}

// Apply 内部流程（control 包，串行执行）
//  1. 读文件 + 解析 + 校验
//  2. 编译规则（规则集 + 预筛自动机）
//  3. 跑内置正负语料自测
//  4. 构造新 Snapshot
//  5. atomic.Pointer 原子替换
// 任何一步失败 → 不替换，旧快照继续服务，错误原样返回给调用方（控制台会回显）
```

**自测**：内置语料里每条必须拦的样本必须被拦、每条不能拦的样本必须不被拦。任何一条不满足则拒绝加载并告警。这防止手滑的宽泛正则直接把线上打挂。

**串行**：`Apply` 用单写者锁保护，两个运维同时保存不会互相覆盖 —— 后来者会看到前者的结果或拿到明确的"版本已变化"错误。

不可热加载的配置（`listen` 地址、控制台监听地址、TLS 私钥路径）改动后标记 `pending_restart`，通过 `/api/v1/config` 暴露，控制台与日志都提醒。

---

## 14. 可观测性

### 14.1 审计日志

JSON Lines，一行一事件。字段：

```json
{
  "ts": "2026-10-03T12:00:00.123Z",
  "tx_id": "a1b2c3d4e5f60718",
  "verdict": "block",
  "score": 5,
  "client_ip": "203.0.113.7",
  "method": "POST",
  "uri": "/api/login",
  "status": 403,
  "upstream_ms": 0,
  "total_ms": 1.8,
  "ruleset_version": "sha256:9f3c…",
  "events": [
    {
      "rule_id": "SQLI-942100",
      "phase": 2,
      "category": "sqli",
      "severity": "critical",
      "score": 5,
      "target": "ARGS:username",
      "operator": "detectSQLi",
      "detail": "sqli fingerprint: union select",
      "matched_len": 28
    }
  ],
  "mode": "block",
  "parse_error": null
}
```

原则：

- **默认不记录 payload 原文**，只记目标名、算子、命中长度与指纹描述。防止审计日志本身变成敏感数据泄露点和存储炸弹。
- 需要取证时用 `log.capture_payload: true`（默认关）或在 `donothackctl replay` 里按 tx_id 从 ring buffer 取。
- 内存里保留最近 N 条命中事件的 ring buffer（按 profile：`small` 256 / `medium` 1024 / `large` 4096），供 `GET /admin/events` 秒级排查。**必须定长**，否则就是一条内存增长路径。
- 日志写入异步 goroutine + 有界 channel，队列满时**丢弃并计数**（宁可丢日志不能阻塞请求），丢弃数进指标。
- 内置按大小+时间轮转，不依赖 logrotate。

### 14.2 指标（Prometheus 文本格式，`/metrics`）

```
donothack_requests_total{mode,verdict}                    counter
donothack_request_duration_seconds{phase}                 histogram
donothack_rule_hits_total{rule_id,category,severity}      counter
donothack_verdict_total{verdict}                          counter
donothack_blocked_total{rule_id}                          counter
donothack_parse_errors_total{reason}                      counter
donothack_body_truncated_total{direction}                 counter
donothack_ratelimit_rejected_total{key_type}              counter
donothack_banned_ips_current                             gauge
donothack_ruleset_version_info{version,loaded_at}         gauge
donothack_ruleset_reload_total{result}                    counter
donothack_upstream_errors_total{reason}                   counter
donothack_audit_dropped_total                             counter
donothack_go_goroutines / donothack_go_memstats_*              runtime
```

`donothack_rule_hits_total` 是**误报治理的核心数据源**：检测模式跑一段时间后，按 rule_id 看命中量和命中样本，人工复核误报率，再决定哪条规则够格进拦截档。

### 14.3 健康与探针

| 端点 | 用途 | 行为 |
| --- | --- | --- |
| `/healthz` | liveness | 进程活着就 200，不检查依赖 |
| `/readyz` | readiness | 配置已加载、规则集非空、上游 DNS 可解析 → 200；否则 503 |
| `/metrics` | 指标 | 可配绑定地址与是否暴露 |
| `/api/v1/*` | 控制面 API | 独立监听端口，默认 `127.0.0.1:9443`，认证见 `docs/CONSOLE.md` §3 |

**控制面（P4 起）**：完整 REST API 见 `docs/CONSOLE.md` §5，关键端点如 `POST /api/v1/rulesets/reload`、`GET /api/v1/rules`、`POST /api/v1/rules/test`（提交原始请求，返回完整命中链路，用于调规则）、`GET /api/v1/events`、`GET /api/v1/events/stream`（SSE）、`GET/PUT /api/v1/config`（带 `Preview`）。

控制面与数据面严格分离：**所有写操作只能走 `control.Apply`**（校验 → 内置语料自测 → 原子替换 → 失败回滚），数据面只读不可变快照。契约见 `docs/CONSOLE.md` §2。

### 14.4 告警钩子

触发条件可配：

- 单规则命中量 1 分钟内突增超过基线 10 倍（可能被集中扫描）
- 规则集加载失败
- 上游错误率超 5%
- 审计日志丢弃 > 0
- 解析错误率超 1%

动作：结构化日志 `level=alert`、可配 webhook（POST JSON）、可选邮件（P5 再议）。

---

## 15. 性能设计

**首要约束是"低配 VPS 也要能跑"。** 完整的性能预算、优化手段、构建参数、降级策略与验收门禁见 `docs/PERFORMANCE.md`，本节只列架构层面的手段与结论。

### 15.1 分级 profile

启动时按 cgroup 自动探测内存与 CPU，选 `small` / `medium` / `large` 三档，档位决定检查上限、连接上限、规则集上限、GOGC 与 GOMEMLIMIT。

**目标机型是 `medium`（2 vCPU / 2 GiB），`small`（1 vCPU / 512 MiB）是必须保证能跑的最低线。**

| 项 | `small`（1 vCPU / 512 MiB） | `medium`（2 vCPU / 2 GiB，**目标档**） | `large` |
| --- | --- | --- | --- |
| 请求体检查上限 | 128 KiB | 512 KiB | 1 MiB |
| 最大并发连接 | 256 | 1024 | 4096 |
| 规则集上限 | 400 条 | 2000 条 | 10000 条 |
| 空载 / 满负载内存目标 | < 15 / 48 MiB | < 25 / 120 MiB | < 80 / 600 MiB |
| 吞吐目标（1 KiB GET） | ≥ 3000 rps | ≥ 8000 rps | ≥ 20000 rps |
| HTTP/2 与 h2c | 关 | 关（明文站用不上；启用 TLS 时可开） | 开 |

响应体检查上限不再需要 —— 本轮不做响应侧检测，响应纯流式透传。

### 15.2 架构层面的手段

| 手段 | 说明 |
| --- | --- |
| **变换链去重 + 单次 AC 扫描** | 低配下最重要的优化。编译期把全部规则的变换链归一化去重（实践中 300 条规则只有 5~10 条不同链），运行期每个不同链只算一次、只扫一次，命中候选再跑昂贵算子。详见 `PERFORMANCE.md` §4。 |
| **响应零缓冲** | 不做响应侧检测，响应直接流式透传回客户端，省掉整块响应缓冲的内存与延迟。这也是砍掉响应检测换来的最大性能收益。 |
| **热路径零分配** | 低核数下 GC 是主要 CPU 消耗。`BenchmarkEngine_NoMatch` 硬门禁 0 allocs/op，端到端 donothack 自身新增分配 ≤ 2 allocs/req。禁用 `net/url` 解析、`strings.Split`、热路径 `fmt.Sprintf` 与字符串转换。 |
| RE2 | 全部正则走 Go 标准库，线性时间，天然免疫 ReDoS；禁止引入 PCRE。 |
| sync.Pool | 事务对象、解码 buffer、变换输出、审计序列化 buffer、JSON 解析器状态全部池化，归还时 reset 且不持有 body 引用。 |
| 原子规则集 | `atomic.Pointer` 无锁读取，reload 不影响在途请求。 |
| 惰性解析 | 阶段 1 不解析请求体；没有阶段 2 规则时 body 完全不解码。 |
| 惰性展开 | 同一 target 在一阶段内只展开一次。 |
| 零拷贝 | 只读检测不复制 body；变换才产生新切片。请求体透传（未进检测的大 body）与响应转发必须转发 `io.WriterTo`/`io.ReaderFrom`，保住 Linux splice 快路径。 |
| 有界检查 | 请求体、连接数、参数个数、值长度、限速表容量、ring buffer 全部有上限，超限截断或淘汰并计数。**无界即漏洞。** |
| 连接与超时 | `MaxHeaderBytes` 压到 32 KiB，配 `ReadHeaderTimeout` / `ReadTimeout` / `WriteTimeout` / `IdleTimeout`，防慢速攻击吃光内存。 |
| 连接复用 | 上游 `http.Transport` 按 profile 调优：`MaxIdleConnsPerHost`、`IdleConnTimeout`、`TCP_NODELAY`。 |
| 快速路径 | 无请求体且无命中时，直接 `io.Copy` 转发，几乎零开销。 |
| 透传豁免 | WebSocket、二进制 `Content-Type`、体积超限 → 直接隧道，不进检测。 |
| 有界降级 | 过载时按 L1→L4 分级降级，状态必须体现在日志、指标与 `/readyz`；`block` 模式只允许 L1，L2 及以上返回 503。见 `PERFORMANCE.md` §8。 |

### 15.3 容量目标（**`medium` 档为主目标，目标值待真机实测**）

`medium`（2 vCPU / 2 GiB）：

- 纯转发 GET：附加延迟 P50 < 0.15ms，P99 < 0.5ms
- 1 KiB body + 全规则评估：P99 < 1.5ms
- 吞吐 ≥ 8000 rps，**相对裸反向代理**降幅 < 10%（相对直连的降幅只作参考，见 PERFORMANCE §2.1 说明）
- 空载常驻 < 25 MiB，满负载 < 120 MiB，压测 30 分钟 RSS 稳定
- reload 期间零请求失败、零连接中断

`small`（1 vCPU / 512 MiB）作为保底线：≥ 3000 rps、满负载 < 48 MiB、P99 < 1.5ms。

**这些是目标值，不是实测值。** 真机基线要在一台 2 核 2 GiB 的 VPS 上跑一次才能确认，方法与脚本见 `PERFORMANCE.md` §10。

### 15.4 明确取舍

不做响应侧检测（范围决定）、超长值尾部深检测、payload 全量留存、多上游编排、分布式限速；`small` 档再额外关 HTTP/2 并收紧请求体与连接上限。逐条影响见 `PERFORMANCE.md` §9。

---

## 16. 安全与健壮性

| 风险 | 处置 |
| --- | --- |
| WAF 自身 panic | 每个请求 goroutine 外层 recover → 500 + fail-open 策略可配；审计记 `panic` |
| 解析耗尽 CPU | 所有解码/解压有迭代次数与输出大小上限 |
| 解压炸弹 | 解压输出上限 = min(声明长度, maxInspectBody × 4) |
| JSON 深层嵌套 | 深度上限 32、节点上限 10000 |
| XXE | XML 解析禁用外部实体 |
| ReDoS | 只用 RE2 |
| 限速绕过 | 严格 XFF 信任链；`trusted_proxies` 为空则忽略 XFF |
| 规则集被篡改 | 启动时校验规则文件哈希（可选签名，P5），规则版本随审计落盘 |
| 管理 API 暴露 | 默认只绑 `127.0.0.1`，token 鉴权，绑定非本地地址时启动告警 |
| 审计日志泄露 | 默认不记 payload |
| fail-open / fail-closed | 默认 fail-open（保业务）；`engine.fail_mode: closed` 可切，但仅在明确要求时用 |
| 内存耗尽（慢速攻击 / 海量连接） | `MaxHeaderBytes` 32 KiB + 读超时 + 并发连接上限 + 限速表容量上限 + 每连接缓冲预算，逐项有界，见 `PERFORMANCE.md` §5.2 |
| 低配 VPS 上 CPU 被 WAF 吃穿 | profile 分级 + 有界降级；`block` 模式禁止静默降级，过载时返回 503 而非放行，见 `PERFORMANCE.md` §8 |
| 自身版本泄露 | `Server` 头默认不发或统一伪造成固定值 |

---

## 17. 测试策略与验收

### 17.1 测试分层

| 层 | 内容 | 位置 |
| --- | --- | --- |
| 单元 | 每个 transform / operator 表驱动，含边界与畸形输入 | `internal/*/*_test.go` |
| 语料回归 | 每条规则配正样本（必拦）与负样本（必不拦） | `testdata/corpus/**` |
| 端到端 | 起真实 donothack 进程 + `httptest` 假上游，走真实 HTTP | `test/e2e/` |
| Fuzz | parser / transform / JSON / multipart 入口 | `*_fuzz_test.go`，CI 跑 60s |
| 基准 | 引擎吞吐、解析开销、内存分配 | `*_bench_test.go` |
| 压测 | 直连 / 裸反向代理 / donothack 三者对比（自带 `cmd/loadgen`，不依赖 hey、wrk） | `scripts/bench.py`，报告进 `docs/bench/` |
| 自测门禁 | 内置语料，热加载前必跑 | `internal/rules/selftest.go` |

### 17.2 语料组织

```
testdata/corpus/
  sqli/
    positive/*.http      # 必须被拦
    negative/*.http      # 必须放行
  xss/ rce/ lfi/ rfi/ webshell/ scanner/ protocol/ upload/
```

`.http` 文件格式：原始 HTTP 请求报文（可通过 `donothack test -r file.http` 离线跑）。

正负样本比例要求不低于 1:2，负样本里必须包含**真实业务流量摘录**（例如带单引号的英文文本、含 `<` `>` 的富文本、base64 图片数据的 JSON 字段）。这是控制误报的关键。

### 17.3 每个阶段的验收门

| 阶段 | 验收标准 |
| --- | --- |
| P0 | `donothack -c config.yaml` 起监听；profile 自动探测生效并打印内存预算表；`GOMEMLIMIT` / `GOGC` 按 profile 设置；并发连接上限、`MaxHeaderBytes`、读超时生效；curl 经其访问假上游返回一致内容；结构化访问日志；`/healthz` `/readyz`（含 profile 与预算详情）正常；SIGTERM 优雅停机不丢在途请求；`go vet ./...`、`go test ./...`、`gofmt -l` 全绿；`GOMAXPROCS=1` 下压测脚本能跑出对比表 |
| P1 | 路径规范化与解码链单测全过；`BenchmarkParseQuery` 达到 0 allocs/op；fuzz 60s 无 crash；畸形请求（超长 URI、非法 %转义、截断 multipart、深层 JSON、解压炸弹）全部 fail-open 且审计有记录；各类上限超限行为符合 `PERFORMANCE.md` §5.2 表 |
| P2 | DSL 能加载并编译；regex / pm / contains / detectSQLi / detectXSS 算子可用；**变换链去重与共享 AC 预筛生效**（启动日志打印不同链数量与自动机规模）；`BenchmarkEngine_NoMatch` 达到 0 allocs/op；阶段 1/2 生效；语料回归跑通；`donothack test -r` 可用 |
| P3 | 评分与阈值生效；detect/block 模式可热切；限速与临时封禁生效且状态表容量上限可验证（伪造 IP 喷洒不涨内存）；白名单不误伤；`medium` profile 压测达标（P99 < 0.5ms 纯转发、相对裸代理吞吐降幅 < 10%、满负载 RSS < 120 MiB）且 `small` 保底线达标；L1–L4 降级可用且状态可见 |
| P4 | `control.Apply` 契约生效（失败回滚、错误可诊断）；零停机 reload（含峰值内存校验）验证通过；指标齐全（含池命中率、降级级别）；审计轮转正常；`/api/v1` 鉴权与登录锁定生效；缺自定义头/伪造 Origin 的写操作被拒；操作审计落盘；TLS 开关与证书热加载可用（默认关）；明文 HTTP 与 XFF 还原链路验证通过 |
| P5 | 控制台八个页面可用；`small` 档控制台额外内存 ≤ 8 MiB；事件查询 3 天范围 P99 < 300ms；含 `<script>` 的 payload 在列表页不回显原文；CSP 无 `unsafe-inline`；CLI 与控制台共用同一套 API |
| P6 | 内置规则集覆盖 SQLi/XSS/RCE/LFI/RFI/webshell/扫描器/协议/上传，每条有正负样本；误报治理报告产出；真机 2 核 2 GiB 基线报告与运维文档齐 |

### 17.4 从检测切拦截的判据（不是感觉，是数据）

1. 检测模式在真实流量上跑满至少 7 天。
2. 按 `donothack_rule_hits_total` 取每条规则的命中样本，人工复核。
3. 规则误报率 < 1%，且无一条误报影响业务功能。
4. 该规则单独升级为拦截档（`mixed` 模式按类目控制），观察 24 小时。
5. 全类目都达标后才切 `block`。

### 17.5 性能门禁（**独立于功能测试，单独卡**）

性能不是"以后优化"，是每个阶段的验收项。门禁脚本 `python scripts/perf-gate.py` 超标即非零退出：

| 门禁 | 阈值 | 卡在哪个阶段 |
| --- | --- | --- |
| `BenchmarkParseQuery` | 0 allocs/op | P1 |
| `BenchmarkEngine_NoMatch` | 0 allocs/op，< 20µs/op | P2 |
| `BenchmarkEngine_FullRules` | 候选规则数 < 10，< 45µs/op | P2 |
| 端到端 donothack 自身新增分配 | ≤ 2 allocs/req | P2 起 |
| `medium` 纯转发附加延迟 | P99 < 0.5ms | P3 |
| `medium` 吞吐降幅（对裸反向代理） | < 10% | P3 |
| `medium` 空载 / 满负载 RSS | < 25 MiB / < 120 MiB | P3 |
| `small` 保底线（吞吐 / RSS） | ≥ 3000 rps / < 48 MiB | P3 |
| 30 分钟压测 RSS 增长 | 无单调增长 | P3 |
| 并发连接上限生效 | 超限 503，内存不涨 | P3 |
| reload 期间失败请求数 | 0 | P4 |

每次里程碑跑一次，报告落 `docs/bench/<tag>-<profile>.md`（报告进库，原始数据不进）。

---

## 18. 分阶段路线图

### P0 骨架（可运行）

产出：仓库结构、`go.mod`、配置加载与校验、**profile 自动探测（cgroup v2/v1 退化到 NumCPU + meminfo）与内存预算表**、`GOMEMLIMIT`/`GOGC` 设置、**连接与超时上限（`MaxHeaderBytes`、读超时、并发连接信号量）**、纯转发反向代理、结构化访问日志、`/healthz` `/readyz`、优雅停机、Makefile（`GOAMD64=v1` 钉死）、`cmd/loadgen` 与 `cmd/testupstream` 与 `cmd/plainproxy`、`scripts/lint.py` 门禁、`scripts/bench.py`、`scripts/passthrough.py`、systemd 单元模板。

交付判据：能起服务、能转发、能停、测试通过、`GOMAXPROCS=1` 下压测脚本能出对比表。打 tag `v0.1.0-mvp`。

**P0 就把性能地基打好**（profile、上限、内存控制），而不是等功能齐了再补 —— 上限和池化是侵入式的，事后加会返工。

### P1 解析层

产出：`parser` 全量（路径规范化、解码链、**零分配 query 解析器**、form/multipart/JSON/XML、解压、逐项上限控制）、`tx` 包与对象池、fuzz 测试。

交付判据：畸形输入不崩、fail-open、审计可查、`BenchmarkParseQuery` 达到 0 allocs/op。

### P2 规则引擎

产出：`transform`、`operator`（regex / pm / contains / startsWith / eq / detectSQLi / detectXSS / entropy / luhn / ipMatch）、`rules`（YAML 加载、编译、索引、**变换链去重 + 共享 Aho-Corasick 预筛**）、`engine` 阶段 1/2、`donothack test -r`、`python scripts/perf-gate.py`、`docs/RULES.md` 定稿。

交付判据：规则能写、能加载、能命中、能离线自测、`BenchmarkEngine_NoMatch` 达到 0 allocs/op。

### P3 决策与防护动作

产出：评分累积、模式切换、`actions`（block/log/tarpit/challenge/custom page）、`ratelimit`（令牌桶 + 滑动窗口 + 临时封禁 + **带容量上限与 LRU 淘汰的 memory store**）、**L1–L4 有界降级**、`realip` 严格信任链、压测脚本与 `medium` 基线报告（附 `small` 保底线）。

交付判据：`medium` profile 压测达标、`small` 保底线达标、误报不炸、伪造源 IP 喷洒不打爆内存。

### P4 运维后端与可靠性（控制台的前提）

产出：`control`（`Snapshot` / `Apply` / `Preview` / `Subscribe`，单写者串行、失败回滚）、`audit`（JSON Lines + 轮转 + ring buffer + 分钟聚合桶 + 有界队列丢弃计数）、`metrics`（含池命中率、降级级别、内存预算）、`admin`（完整 `/api/v1`、认证 basic/session/both、失败锁定、CSRF、操作审计、pprof 默认关）、`alert`、零停机 reload 与失败回滚、TLS 与证书热加载（默认关）、h2 随 TLS 可选、Redis 限速后端（可选）。

交付判据：reload 零失败请求且峰值内存符合预算表；`Apply` 失败时线上状态不变且错误可诊断；缺自定义头或伪造 Origin 的写操作被拒；5 次登录失败后锁定生效；指标齐全，探针正确，降级状态三处可见，明文 HTTP + XFF 还原链路验证通过。

### P5 Web 控制台

产出：`web/` 原生 ES module SPA（概览 / 事件 / 规则 / 规则测试台 / 例外白名单 / CC 限速 / 系统设置 / 操作审计 八个页面）、`internal/console` 静态资源服务（embed、CSP、缓存、gzip）、`cmd/donothackctl` 走同一套 API。

交付判据：`small` 档下页面可用且控制台额外内存 ≤ 8 MiB；事件查询 3 天范围 P99 < 300ms；**用一条含 `<script>` 的 payload 验证列表页不回显原文**；CSP 无 `unsafe-inline`；公网明文绑定必须显式 `allow_insecure` 才能启动。详见 `docs/CONSOLE.md` §10。

### P6 规则集与投产

产出：全类目内置规则集（每条带正负样本）、误报治理报告、SecRules 兼容层（视情况）、运维手册（含 systemd / Docker / 低配调优 / 控制台使用）、**真机 2 核 2 GiB 性能基线与容量报告（附 1 核 512 MiB 保底线数据）**、发布流程。

交付判据：检测模式 7 天数据支撑，逐类目切拦截；真机基线与 `PERFORMANCE.md` §2 目标对齐（不达标就改实现或改目标，不允许留一张对不上的表）。

### P7 多站点（后置）

产出：数据面按 Host 路由到不同上游与规则集、站点级证书与开关、控制台站点管理页与站点切换器。`Snapshot` 从单站点扩为 `[]Site`。

交付判据：一个控制台可管多个站点，站点间规则与上游互不影响。

---

## 19. Git 工作流

- `main` 只接受：`gofmt -l` 无输出、`go vet ./...` 通过、`go test ./...` 通过的提交。
- 每个功能走 `feat/<阶段>-<模块>` 分支（如 `feat/p1-parser`），完成后照常合并回 `main`（保留分支历史，便于对照）。
- 提交信息：`type(scope): 描述`，`type ∈ feat|fix|perf|refactor|test|docs|chore|build`。一次提交一件事，不混杂。
- 每个里程碑打 annotated tag：`v0.1.0-mvp`、`v0.2.0-parser`、`v0.3.0-engine`、`v0.4.0-actions`、`v0.5.0-ops`、`v1.0.0`。
- 回滚：`git checkout <tag>` 或 `git revert <sha>`。
- 对照：`git diff v0.2.0-parser..v0.3.0-engine`。
- `CHANGELOG.md` 每个里程碑更新，写清"改了什么、怎么验证、怎么回滚"。
- 规则集文件独立提交（`rules/*.yaml` 单独一个提交），这样规则误拦时能单独 revert 规则而不动代码。

---

## 20. 未决问题

1. **模块路径与命名**：已定 —— 产品与二进制都叫 `donothack`，Go 模块路径 `donothack`（裸路径，私有工具够用；若将来要 `go get` 再换成带域名的路径，是一次机械替换）。
2. **SecRules 兼容层范围**：全量兼容（含 `SecRuleUpdateTargetById`、链式规则 `chain`）工作量很大。建议先做"读取 CRS 规则的一个子集"（`SecRule` + `@rx`/`@pm`/`@detectSQLi` + `t:xxx` + `id:`/`msg:`/`severity:`），P5 再评估。注意 CRS 里有大量响应侧规则（phase 3/4），本轮不实现。
3. **libinjection 自研还是移植**：建议自研精简版（SQLi 词法状态机 + XSS 上下文识别），避免 CGO 与许可证问题。需要评估检测率是否够用。
4. **多上游与服务发现**：P5 之后是否需要。
5. **Redis 是否必须**：单副本部署时不需要。若确定多副本，P3 就要把 `Store` 接上，不要拖到上线前。
6. **TLS 证书来源**：明文 HTTP 是常见场景，TLS 默认关。需要时先做文件热加载，ACME 自动签发后置。
7. **Web 控制台**：**要做**（P5），设计与安全要求见 `docs/CONSOLE.md`。此前"不做 GUI，管理走 API + 命令行"的判断作废 —— 生产运维需要浏览器里就能看攻击、改规则、加白名单。控制台与数据面同进程同二进制（`go:embed`），前端是原生 ES module SPA，无 Node 构建链。多站点（雷池式）后置为 P7。
8. **响应侧检测是否永远不做**：本轮按需求收窄砍掉。若将来要加，代价见 §12，需要重新算性能预算。
9. **限速/封禁是否保留**：需求只提了"识别请求里的攻击 payload"，限速属于附加能力。当前设计保留（成本低、不涉及响应缓冲），默认开。若不需要，可整模块关掉。
10. **目标 VPS**：已定 2 核 2 GiB（`medium` 为目标档），1 核 512 MiB 为保底线。**仍需一台真机跑基线**，否则 §15.3 的数字只能标注"未经实测"。
11. **控制台准入**：已定 —— 第一层 Basic 门槛挡扫描器（统一 401，不区分路径），第二层表单登录 + 会话做认证；门槛凭据与账号分开；TLS 强制（未配证书则自动自签）。是否要再加一层随机路径见 `docs/CONSOLE.md` §11。
12. **多站点（P7）是否真要做**：当前单站点，数据结构按 `[]Site` 预留。若确定要，P4 的 `Snapshot` 结构就要一次到位，别等 P7 再动。
13. **payload 展示**：已定用绝对代码模式（`<pre><code>` + `textContent`，全站禁 `innerHTML`，CI 门禁）。列表页只显示摘要，详情页展开代码块；原文是否落盘仍由 `log.capture_payload` 控制，默认关。

---

## 附录 A：一次 SQLi 请求的完整走位

请求：

```
POST /api/login HTTP/1.1
Host: example.com
Content-Type: application/json

{"user":"admin'/**/UNION/**/SELECT/**/1,password/**/FROM/**/users--","pass":"x"}
```

走位：

1. `realip` → `203.0.113.7`（无 XFF，直接用对端）。
2. 阶段 1：请求头无异常；`Content-Type: application/json` 决定 body 解析策略。
3. 阶段 2：读 body（54 字节 < 128 KiB），递归展开 → `ArgsJSON["user"] = "admin'/**/UNION/**/SELECT/**/1,password/**/FROM/**/users--"`，同时并入 `Args`。
4. 预筛：AC 机在 `Args` 值里命中字面量 `union`、`select` → 候选规则含 `SQLI-942100`。
5. `SQLI-942100` 用 `t:removeComments,urlDecode,compressWhitespace,lowercase` 变换 → `admin' union select 1,password from users--`。
6. `detectSQLi` 算子判定命中，`detail: "sqli fingerprint: union select"`，`target: ARGS:user`。
7. 类目 `sqli` 加 5 分，达到入站阈值 5。
8. 裁决 block → 403 + `X-Request-ID`，不回显 payload。
9. 审计 JSON 落盘，`donothack_rule_hits_total{rule_id="SQLI-942100"}` +1。
10. 上游从未收到这个请求。

## 附录 B：配置示例（初稿，P0 实现后对齐）

```yaml
profile: medium            # small | medium | large | auto（按 cgroup 探测；探测失败按 medium）
                           # 下面的数值是 medium 档默认值（目标机型 2 vCPU / 2 GiB）
                           # small/large 见 docs/PERFORMANCE.md §1

listen:
  addr: "0.0.0.0:8080"
  max_header_bytes: 32768  # 默认 1MiB 太大，低配下是内存放大点
  read_header_timeout: 5s  # 防 slowloris
  read_timeout: 15s
  write_timeout: 30s
  idle_timeout: 60s
  max_conns: 1024          # 并发连接上限（信号量，超限 503）
  http2: false             # 明文 HTTP 站用不上；启用 TLS 时可开

upstream:
  url: "http://127.0.0.1:9000"
  dial_timeout: 5s
  response_header_timeout: 30s
  max_idle_conns_per_host: 64
  idle_conn_timeout: 30s
  tcp_nodelay: true

tls:
  enabled: false           # 默认关：站点可能就跑明文 HTTP
  cert_file: ""
  key_file: ""
  min_version: "1.2"

real_ip:
  trusted_proxies: []      # 空 = 忽略 XFF，直接用对端
                           # 明文站前面若有 nginx/CDN，必须填对，否则限速与封禁形同虚设
  header: "X-Forwarded-For"

engine:
  mode: detect             # detect | block | mixed
  fail_mode: open          # open | closed
  degrade: auto            # auto | off —— 过载分级降级，见 docs/PERFORMANCE.md §8
                           # block 模式下只允许 L1；L2 及以上拒绝降级并返回 503
  inbound_anomaly_threshold: 5
  # outbound_anomaly_threshold 保留但不生效（本轮不做响应侧检测）

rules:
  dir: "./rules"
  files: ["*.yaml"]
  reload_interval: 0s      # 0 = 只靠 SIGHUP / admin API
  self_test: true

limits:
  max_inspect_body: 524288      # 512 KiB（medium）
  max_uri_length: 8192
  max_headers: 100
  max_params: 1000
  max_param_value_len: 65536
  max_json_depth: 32
  max_json_nodes: 10000
  max_transform_depth: 8
  max_prefilter_literals: 60000
  max_rules: 2000
  ratelimit_table_capacity: 65536   # 必须有上限，否则伪造源 IP 喷洒可打爆内存
  ring_buffer_size: 1024

ratelimit:
  enabled: true
  default_rps: 100
  default_burst: 200
  ban_after_hits: 20
  ban_window: 60s
  ban_duration: 300s
  whitelist: []

log:
  level: info
  format: json
  file: "./logs/donothack.jsonl"
  max_size_mb: 100
  max_backups: 10
  capture_payload: false

metrics:
  enabled: true
  addr: "127.0.0.1:9090"   # 也可复用主监听 /metrics

admin:
  enabled: true
  addr: "0.0.0.0:9443"      # 控制台 + /api/v1 监听地址
  gate:                     # 第一层：Basic 门槛，挡扫描器（不是安全边界）
    enabled: true
    mode: basic             # basic（默认）| none
    realm: "Restricted"     # 中性字符串，不暴露产品特征
    username: "gate"
    password_hash: ""       # 与登录账号分开；为空则自动生成并打印
    path_token: ""          # 可选额外一层：控制台挂随机路径（Basic 已挡住路径暴露，非必需）
    exempt_api_token: true  # 带 X-Donothack-Token 的请求跳过门槛，方便 CLI
    probe_ban_window: 60s   # 同 IP 门槛失败窗口
    probe_ban_after: 20     # 达此次数则封禁
    probe_ban_duration: 15m
  tls:
    enabled: true           # 门槛用 Basic ⇒ TLS 强制
    cert_file: ""           # 为空则首次启动自动生成自签证书并打印指纹
    key_file: ""
    auto_self_signed: true
  auth_mode: session        # 第二层：session | session+basic
  username: "admin"
  password_hash: ""         # PBKDF2-HMAC-SHA256 600k 迭代；为空则控制台不启动并打印生成命令
  api_token: ""             # CLI 与脚本用；可单独生成与轮换
  totp_enabled: false
  allow_ips: []             # 可选 IP 白名单
  allow_insecure: false     # 绑非本地地址且未启 TLS 时必须显式设 true 才启动
  session_idle_timeout: 30m
  max_login_fails: 5        # 单 IP 失败上限
  lockout: 15m
  pprof: false              # 默认关，只在 127.0.0.1 可用
  events:
    retention_days: 7
    retention_bytes: 536870912
    max_query_range: 24h    # 控制台单次查询最大时间范围
    max_rows: 200
    query_timeout: 3s
    sqlite: false           # 纯 Go SQLite 富查询，medium/small 默认关

alert:
  enabled: false
  webhook: ""
```

---

## 附录 C：待确认清单（评审时逐条打勾）

已定（2026-10-06 评审）：

- [x] 产品与二进制名 `donothack`，Go 模块路径 `donothack`
- [x] 部署形态：独立反向代理
- [x] 规则体系：自研 YAML DSL，预留 SecRules 兼容层
- [x] 默认模式：`detect` 只记录不拦
- [x] 目标机型：2 vCPU / 2 GiB（`medium` 为目标档），1 vCPU / 512 MiB 为保底线
- [x] 检测范围：**只做请求侧**（请求头、请求体、参数），响应侧不做
- [x] TLS 默认关（站点可能跑明文 HTTP）
- [x] **必须有 Web 控制台**（对标雷池），单站点先行、多站点后置 P7
- [x] 控制台前端用原生 ES module SPA，不引 Node 构建链
- [x] 控制台可公网访问 —— 因此 TLS、登录失败锁定、写操作自定义头 + Origin 校验为**强制项**
- [x] 控制台准入：第一层 **HTTP Basic 门槛**（未过则一切路径统一 401，登录页/路径/API/产品指纹整体不可见），第二层**表单登录 + 会话**做认证；门槛凭据与登录账号分开；因门槛用 Basic，TLS 强制（首次启动自动生成自签证书）
- [x] payload 展示用**绝对代码模式**（`<pre><code>` + `textContent`，全站禁 `innerHTML` 并加 CI 门禁，不引第三方 markdown 库）——“看得见”与“安全”同时满足

仍待确认：

- [ ] 目录划分是否合理
- [ ] §9.1 变换链去重 + 共享预筛方案是否认可（性能关键，实现复杂度不低）
- [ ] §10 评分阈值是否认可
- [ ] §11 限速默认值是否认可，以及限速/封禁是否要保留（需求只提了 payload 识别，限速属附加）
- [ ] §15 性能目标与 profile 分级是否认可
- [ ] §17.5 性能门禁（0 allocs/op 等硬指标）是否认可 —— 这些会让开发速度变慢，但低核数下省不掉
- [ ] 过载降级策略：默认 `auto`、`block` 模式只允许 L1（L2+ 返回 503），是否认可
- [ ] 是否提供真机（2 核 2 GiB）跑一次基线，否则目标值只能标注"未经实测"
- [ ] §18 阶段划分与顺序是否认可（P0 骨架是否过轻）
- [ ] §20 未决问题逐条定调
- [ ] 控制台是否需要多用户与角色（管理员 / 只读运维）
- [ ] 事件保留默认 7 天 / 512 MiB 是否合适
- [ ] 是否需要门槛之外的随机路径（Basic 已挡住路径暴露，此层只是顺手便宜）

# wafd 架构设计

> 状态：待评审（v0 设计稿）
> 目标读者：本项目开发者
> 最后更新：P0 之前

---

## 1. 项目定位

`wafd` 是一个用 Go 编写的、生产环境可用的 Web 应用防火墙，以独立反向代理形态部署在业务服务之前。

一句话：**客户端 → wafd → 上游业务**，请求和响应都过检测流水线，命中则按决策模型放行、记录、拦截、挑战或限速。

### 设计目标

| 目标 | 说明 |
| --- | --- |
| 生产可用 | 不是演示品。零停机热加载、优雅停机、健康探针、可观测性、误报可治理，全部是必备项。 |
| 单二进制 | 纯 Go，无 CGO，`CGO_ENABLED=0` 交叉编译，不依赖 nginx / Apache / Lua / PCRE 动态库。 |
| 低开销 | 无命中路径的附加延迟目标 < 1ms（P99），吞吐相对直连下降 < 15%。 |
| 不成为单点故障 | 任何解析或规则异常都必须 fail-open 放行并留审计，绝不因为 WAF 自身错误导致业务 5xx。 |
| 可对照回滚 | 规则、配置、代码全部进 git，每次决策可追溯到规则 ID 与规则文件版本。 |
| 规则可读可写 | 自研 YAML DSL，安全工程师不需要写 Go 就能加规则；预留 ModSecurity SecRules 兼容层。 |

### 非目标（明确不做）

- **不做 DDoS / 流量清洗**：四层洪水交给上游清洗设备或云厂商，wafd 只处理七层语义。
- **不做内容缓存 / CDN**：不缓存响应体。
- **不做多上游负载均衡编排**：P0–P4 只支持单上游（或简单轮询），服务发现留给 P5 之后。
- **不做分布式协同封禁**：单机内存限速为主；多副本只通过 Redis 共享限速与封禁状态，不做全局威胁情报。
- **不自研 TLS 栈**：用标准库 `crypto/tls`。

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
                    │                      wafd                            │
                    │                                                      │
  Client ──TLS──▶   │  ┌──────────┐   ┌──────────┐   ┌─────────────────┐  │
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
                    │        │  P1 headers ─P2 body ─P3 resp hdr ─P4 │   │
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
                    │   │  proxy (RoundTrip, body tee, ws tunnel)  │──────┼──▶ Upstream
                    │   └────────────────────┬─────────────────────┘      │
                    │                        │                            │
                    │   ┌────────────────────▼─────────────────────┐      │
                    │   │ audit log / metrics / admin API / alert  │      │
                    │   └──────────────────────────────────────────┘      │
                    └──────────────────────────────────────────────────────┘
```

### 数据流（一次请求）

1. 连接进来，`realip` 按信任链解析真实客户端 IP。
2. 建 `Transaction`，分配 tx id、起始时间。
3. 阶段 1：解析请求行与请求头，装填变量集合，跑阶段 1 规则（扫描器指纹、畸形协议、恶意 UA）。
4. 阶段 2：按需读取请求体（受 `maxInspectBody` 限制），解压、解码、解析为参数并跑阶段 2 规则（SQLi、XSS、RCE、LFI、webshell）。
5. 决策：若累计分数超入站阈值或命中硬拦截规则，执行动作（默认 403），写审计，结束。
6. 否则转发上游，`body tee` 保留响应体副本（受 `maxInspectResponse` 限制）。
7. 阶段 3/4：检查响应头与响应体（敏感数据泄露、报错回显、webshell 回连特征）。
8. 阶段 5：收尾，写审计日志、更新指标。

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

	// 响应侧（阶段 3/4 装填）
	ResStatus  int
	ResHeaders Params
	ResBody    []byte
	ResTruncated bool

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
cmd/wafd/              main：命令行解析、装配、信号处理
cmd/wafdctl/           管理客户端（reload、规则自测、状态查询）——可选，P4

internal/config/       配置结构体、YAML 加载、校验、默认值、热加载协调
internal/tx/           Transaction、Collections、Event、Verdict、Score 定义
internal/parser/       请求/响应 → Collections（路径规范化、解码链、解压、JSON/XML/multipart）
internal/transform/    变换函数注册表与实现
internal/operator/     算子注册表与实现（regex、pm、detectSQLi、detectXSS、entropy、luhn、ipMatch…）
internal/rules/        规则模型、YAML 加载、编译、索引、RuleSet 与原子替换
internal/engine/       阶段流水线调度、分数累计、决策
internal/actions/      block / log / tarpit / challenge / ratelimit 执行器
internal/ratelimit/    令牌桶与滑动窗口、临时封禁、状态后端接口（memory / redis）
internal/proxy/        反向代理、body tee、WebSocket 隧道、连接池
internal/realip/       可信代理链与真实 IP 还原
internal/audit/        结构化审计日志、文件轮转、异步写入
internal/metrics/     Prometheus 指标
internal/admin/       管理 API（reload、规则自测、统计查询）
internal/alert/        告警钩子（webhook / 日志标记）
internal/version/      版本、构建信息（ldflags 注入）
rules/                 内置规则集（YAML）
testdata/              语料（正/负样本）
docs/                  设计文档、规则文档、压测报告
scripts/               压测、语料回归、构建脚本
```

### 依赖方向（只允许自上而下）

```
cmd/wafd
  └─ config
  └─ proxy ─┬─ engine ─┬─ rules ─┬─ parser
            │          │         ├─ transform
            │          │         └─ operator
            │          ├─ actions ─ ratelimit
            │          └─ tx
            ├─ realip
            └─ audit / metrics / alert
  └─ admin ──── rules / engine / metrics
```

`tx` 是最底层，不依赖任何其他内部包。`parser`、`transform`、`operator` 互不依赖。**禁止循环依赖**，用 `go vet` + CI 卡住。

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
	// Phase1 请求头；可能直接返回终止裁决
	Phase1(ctx context.Context, t *tx.Transaction) (tx.Verdict, error)
	Phase2(ctx context.Context, t *tx.Transaction) (tx.Verdict, error)
	Phase3(ctx context.Context, t *tx.Transaction) (tx.Verdict, error)
	Phase4(ctx context.Context, t *tx.Transaction) (tx.Verdict, error)
	Phase5(ctx context.Context, t *tx.Transaction)
}
```

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

- 请求体检查上限 `limits.max_inspect_body`，默认 1 MiB；超限只检查前 N 字节，`BodyTruncated=true` 进审计。**不因为超限就拒绝**（大文件上传是正常业务）。
- 响应体检查上限 `limits.max_inspect_response`，默认 512 KiB。
- 二进制响应（`Content-Type` 非文本，或 `Content-Type` 缺失但魔数匹配常见二进制格式）跳过阶段 4，只查响应头。
- `Content-Length` 与实际不符 → 记分（请求走私迹象）。
- 同时出现 `Content-Length` 与 `Transfer-Encoding` → 记分（HTTP 请求走私）。

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
2. **字面量预筛**：对算子的模式提取最长字面量子串（如 `regex: "(?i)union\s+select"` → `union`），建 Aho-Corasick 机。请求进来先用一次 AC 扫描拿到"可能命中的规则集合"，再只对这几十条跑昂贵算子（如 libinjection、复杂正则）。**这是性能的主要来源。**
3. **变换链合并**：同一规则内多个 target 共用相同变换前缀时，只算一次。
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
  outbound_anomaly_threshold: 4    # 出站
  categories:
    sqli:     5
    xss:      5
    rce:      5
    lfi:      5
    rfi:      5
    webshell: 5
    scanner:  3
    protocol: 5
    leakage:  4
    upload:   3
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

## 12. 响应侧检测

响应检测的目的不是拦攻击者，而是**阻止利用成功后的数据外带和回显**：

- 敏感数据泄露：身份证、银行卡（Luhn 校验）、手机号、私钥（`-----BEGIN ... PRIVATE KEY-----`）、云厂商 AK/SK 形态、JWT。
- 报错回显：`SQL syntax`、`ORA-`、`Warning: mysql_`、Go panic 栈、Java 堆栈。
- Webshell 特征：响应体含 `eval(`、`base64_decode(` 且请求侧有可疑参数。
- 响应头安全校验（可选，记分不拦）：缺 `X-Content-Type-Options`、缺 `Content-Security-Policy`、`Server` 头版本泄露。

响应体检测的难点是**流式响应**。策略：先缓冲到 `max_inspect_response`，检查完再一次性写给客户端；超过上限则边转发边检查前 N 字节，后续透传。对 SSE / chunked 长连接，只检查第一批数据块。

---

## 13. 配置系统

### 13.1 配置结构

```go
// internal/config
type Config struct {
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

### 13.2 热加载

```go
// 监听 SIGHUP 或 POST /admin/reload
func (m *Manager) Reload(path string) error {
	next, err := load(path)          // 1. 读 + 解析 + 校验
	if err != nil { return err }     //    失败 → 保留旧配置，报错返回
	rs, err := rules.Compile(next)   // 2. 编译规则
	if err != nil { return err }
	if err := selfTest(rs); err != nil { return err }  // 3. 内置正负语料自测
	// 4. 全部通过才原子切换
	applyConfig(next)
	rules.Swap(rs)
	return nil
}
```

**自测**：内置语料里每条必须拦的样本必须被拦、每条不能拦的样本必须不被拦。任何一条不满足则拒绝加载并告警。这防止手滑的宽泛正则直接把线上打挂。

不可热加载的配置（`listen` 地址、TLS 私钥路径）改动后标记 `pending_restart`，通过管理 API 暴露，日志提醒。

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
- 需要取证时用 `log.capture_payload: true`（默认关）或在 `wafdctl replay` 里按 tx_id 从 ring buffer 取。
- 内存里保留最近 1000 条命中事件的 ring buffer，供 `GET /admin/events` 秒级排查。
- 日志写入异步 goroutine + 有界 channel，队列满时**丢弃并计数**（宁可丢日志不能阻塞请求），丢弃数进指标。
- 内置按大小+时间轮转，不依赖 logrotate。

### 14.2 指标（Prometheus 文本格式，`/metrics`）

```
wafd_requests_total{mode,verdict}                    counter
wafd_request_duration_seconds{phase}                 histogram
wafd_rule_hits_total{rule_id,category,severity}      counter
wafd_verdict_total{verdict}                          counter
wafd_blocked_total{rule_id}                          counter
wafd_parse_errors_total{reason}                      counter
wafd_body_truncated_total{direction}                 counter
wafd_ratelimit_rejected_total{key_type}              counter
wafd_banned_ips_current                             gauge
wafd_ruleset_version_info{version,loaded_at}         gauge
wafd_ruleset_reload_total{result}                    counter
wafd_upstream_errors_total{reason}                   counter
wafd_audit_dropped_total                             counter
wafd_go_goroutines / wafd_go_memstats_*              runtime
```

`wafd_rule_hits_total` 是**误报治理的核心数据源**：检测模式跑一段时间后，按 rule_id 看命中量和命中样本，人工复核误报率，再决定哪条规则够格进拦截档。

### 14.3 健康与探针

| 端点 | 用途 | 行为 |
| --- | --- | --- |
| `/healthz` | liveness | 进程活着就 200，不检查依赖 |
| `/readyz` | readiness | 配置已加载、规则集非空、上游 DNS 可解析 → 200；否则 503 |
| `/metrics` | 指标 | 可配绑定地址与是否暴露 |
| `/admin/*` | 管理 API | 默认只监听 `127.0.0.1`，需 token |

管理 API（P4）：`POST /admin/reload`、`GET /admin/rules`、`POST /admin/rule-test`（提交一条规则+样本，返回是否命中，用于调规则）、`GET /admin/events`。

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

| 手段 | 说明 |
| --- | --- |
| 字面量预筛 | 见 §9.1，把每请求规则评估从 O(全部规则) 降到 O(可能命中) |
| RE2 | 全部正则走 Go 标准库，线性时间，天然免疫 ReDoS；禁止引入 PCRE |
| sync.Pool | 解码 buffer、变量值切片、JSON 解析器 |
| 原子规则集 | `atomic.Pointer` 无锁读取，reload 不影响在途请求 |
| 惰性解析 | 阶段 1 不解析请求体；只有存在阶段 2 规则时才读 body |
| 惰性展开 | 同一 target 在一阶段内只展开一次 |
| 零拷贝 | 只读检测不复制 body，变换才产生新切片 |
| 有界检查 | body/response 上限截断，避免大文件拖慢 |
| 连接复用 | 上游 `http.Transport` 调优：`MaxIdleConnsPerHost`、`IdleConnTimeout` |
| 快速路径 | 无任何请求体且无命中时，直接 `io.Copy` 转发，几乎零开销 |
| 透传豁免 | WebSocket、`Content-Type` 为二进制、体积超限 → 直接隧道 |

容量目标（本机基准，4C8G，keep-alive）：

- 无规则命中：附加延迟 P50 < 0.2ms，P99 < 1ms
- 吞吐：相对直连上游下降 < 15%
- 单实例 ≥ 8000 QPS（简单 GET，规则集约 300 条）
- 常驻内存 < 100 MiB，压测 30 分钟后 RSS 稳定（无泄漏）
- reload 期间零请求失败、零连接中断

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
| 自身版本泄露 | `Server` 头默认不发或统一伪造成固定值 |

---

## 17. 测试策略与验收

### 17.1 测试分层

| 层 | 内容 | 位置 |
| --- | --- | --- |
| 单元 | 每个 transform / operator 表驱动，含边界与畸形输入 | `internal/*/*_test.go` |
| 语料回归 | 每条规则配正样本（必拦）与负样本（必不拦） | `testdata/corpus/**` |
| 端到端 | 起真实 wafd 进程 + `httptest` 假上游，走真实 HTTP | `test/e2e/` |
| Fuzz | parser / transform / JSON / multipart 入口 | `*_fuzz_test.go`，CI 跑 60s |
| 基准 | 引擎吞吐、解析开销、内存分配 | `*_bench_test.go` |
| 压测 | wrk / hey 对比直连与经过 wafd | `scripts/bench.ps1`，报告进 `docs/bench/` |
| 自测门禁 | 内置语料，热加载前必跑 | `internal/rules/selftest.go` |

### 17.2 语料组织

```
testdata/corpus/
  sqli/
    positive/*.http      # 必须被拦
    negative/*.http      # 必须放行
  xss/ rce/ lfi/ rfi/ webshell/ scanner/ protocol/ upload/
```

`.http` 文件格式：原始 HTTP 请求报文（可通过 `wafd test -r file.http` 离线跑）。

正负样本比例要求不低于 1:2，负样本里必须包含**真实业务流量摘录**（例如带单引号的英文文本、含 `<` `>` 的富文本、base64 图片数据的 JSON 字段）。这是控制误报的关键。

### 17.3 每个阶段的验收门

| 阶段 | 验收标准 |
| --- | --- |
| P0 | `wafd -c config.yaml` 起监听；curl 经其访问假上游返回一致内容；结构化访问日志；`/healthz` `/readyz` 正常；SIGTERM 优雅停机不丢在途请求；`go vet ./...`、`go test ./...`、`gofmt -l` 全绿 |
| P1 | 路径规范化与解码链单测全过；fuzz 60s 无 crash；畸形请求（超长 URI、非法 %转义、截断 multipart、深层 JSON）全部 fail-open 且审计有记录 |
| P2 | DSL 能加载并编译；regex / pm / contains / detectSQLi / detectXSS 算子可用；阶段 1/2 生效；语料回归跑通；`wafd test -r` 可用 |
| P3 | 评分与阈值生效；detect/block 模式可热切；限速与临时封禁生效；白名单不误伤；压测达标（P99 < 1ms，吞吐降幅 < 15%） |
| P4 | 响应侧检测生效；零停机 reload（含失败回滚）验证通过；指标齐全；审计轮转正常；管理 API 鉴权生效 |
| P5 | 内置规则集覆盖 SQLi/XSS/RCE/LFI/RFI/webshell/扫描器/协议/上传，每条有正负样本；误报治理报告产出；压测报告与运维文档齐 |

### 17.4 从检测切拦截的判据（不是感觉，是数据）

1. 检测模式在真实流量上跑满至少 7 天。
2. 按 `wafd_rule_hits_total` 取每条规则的命中样本，人工复核。
3. 规则误报率 < 1%，且无一条误报影响业务功能。
4. 该规则单独升级为拦截档（`mixed` 模式按类目控制），观察 24 小时。
5. 全类目都达标后才切 `block`。

---

## 18. 分阶段路线图

### P0 骨架（可运行）

产出：仓库结构、`go.mod`、配置加载与校验、纯转发反向代理、结构化访问日志、`/healthz` `/readyz`、优雅停机、Makefile、CI（本地脚本）。

交付判据：能起服务、能转发、能停、测试通过。打 tag `v0.1.0-mvp`。

### P1 解析层

产出：`parser` 全量（路径规范化、解码链、query/form/multipart/JSON/XML、解压、上限控制）、`tx` 包、fuzz 测试。

交付判据：畸形输入不崩、fail-open、审计可查。

### P2 规则引擎

产出：`transform`、`operator`（regex / pm / contains / startsWith / eq / detectSQLi / detectXSS / entropy / luhn / ipMatch）、`rules`（YAML 加载、编译、索引、预筛）、`engine` 阶段 1/2、`wafd test -r`、`docs/RULES.md` 定稿。

交付判据：规则能写、能加载、能命中、能离线自测。

### P3 决策与防护动作

产出：评分累积、模式切换、`actions`（block/log/tarpit/challenge/custom page）、`ratelimit`（令牌桶 + 滑动窗口 + 临时封禁 + memory store）、`realip` 严格信任链、压测脚本与报告。

交付判据：压测达标，误报不炸。

### P4 响应侧与运维

产出：`audit`（JSON Lines + 轮转 + ring buffer）、`metrics`、`admin`（reload / rules / rule-test / events）、`alert`、状态 3/4 规则、零停机 reload 与失败回滚、TLS 与证书热加载、h2/h2c、Redis 限速后端（可选）。

交付判据：reload 零失败请求，指标齐全，探针正确。

### P5 规则集与投产

产出：全类目内置规则集（每条带正负样本）、误报治理报告、SecRules 兼容层（视情况）、运维手册、压测与容量报告、发布流程。

交付判据：检测模式 7 天数据支撑，逐类目切拦截。

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

1. **模块路径与命名**：暂用 `donothack/waf`、二进制 `wafd`。要改趁早。
2. **SecRules 兼容层范围**：全量兼容（含 `SecRuleUpdateTargetById`、链式规则 `chain`）工作量很大。建议先做"读取 CRS 规则的一个子集"（`SecRule` + `@rx`/`@pm`/`@detectSQLi` + `t:xxx` + `id:`/`msg:`/`severity:`），P5 再评估。
3. **libinjection 自研还是移植**：建议自研精简版（SQLi 词法状态机 + XSS 上下文识别），避免 CGO 与许可证问题。需要评估检测率是否够用。
4. **多上游与服务发现**：P5 之后是否需要。
5. **Redis 是否必须**：单副本部署时不需要。若确定多副本，P3 就要把 `Store` 接上，不要拖到上线前。
6. **TLS 证书来源**：文件热加载 vs ACME 自动签发。建议先文件，ACME 后置。
7. **是否要 GUI**：不做。管理走 API + 命令行。

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
3. 阶段 2：读 body（54 字节 < 1 MiB），递归展开 → `ArgsJSON["user"] = "admin'/**/UNION/**/SELECT/**/1,password/**/FROM/**/users--"`，同时并入 `Args`。
4. 预筛：AC 机在 `Args` 值里命中字面量 `union`、`select` → 候选规则含 `SQLI-942100`。
5. `SQLI-942100` 用 `t:removeComments,urlDecode,compressWhitespace,lowercase` 变换 → `admin' union select 1,password from users--`。
6. `detectSQLi` 算子判定命中，`detail: "sqli fingerprint: union select"`，`target: ARGS:user`。
7. 类目 `sqli` 加 5 分，达到入站阈值 5。
8. 裁决 block → 403 + `X-Request-ID`，不回显 payload。
9. 审计 JSON 落盘，`wafd_rule_hits_total{rule_id="SQLI-942100"}` +1。
10. 上游从未收到这个请求。

## 附录 B：配置示例（初稿，P0 实现后对齐）

```yaml
listen:
  addr: "0.0.0.0:8080"
  read_timeout: 30s
  write_timeout: 60s
  idle_timeout: 120s

upstream:
  url: "http://127.0.0.1:9000"
  dial_timeout: 5s
  response_header_timeout: 30s
  max_idle_conns_per_host: 128

tls:
  enabled: false
  cert_file: ""
  key_file: ""
  min_version: "1.2"

real_ip:
  trusted_proxies: []      # 空 = 忽略 XFF，直接用对端
  header: "X-Forwarded-For"

engine:
  mode: detect             # detect | block | mixed
  fail_mode: open          # open | closed
  inbound_anomaly_threshold: 5
  outbound_anomaly_threshold: 4

rules:
  dir: "./rules"
  files: ["*.yaml"]
  reload_interval: 0s      # 0 = 只靠 SIGHUP / admin API
  self_test: true

limits:
  max_inspect_body: 1048576
  max_inspect_response: 524288
  max_uri_length: 8192
  max_headers: 100
  max_json_depth: 32

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
  file: "./logs/wafd.jsonl"
  max_size_mb: 100
  max_backups: 10
  capture_payload: false

metrics:
  enabled: true
  addr: "127.0.0.1:9090"   # 也可复用主监听 /metrics

admin:
  enabled: true
  addr: "127.0.0.1:9091"
  token: ""                # 必填，空则禁用管理 API

alert:
  enabled: false
  webhook: ""
```

---

## 附录 C：待确认清单（评审时逐条打勾）

- [ ] 模块路径 `donothack/waf`、二进制名 `wafd` 是否可用
- [ ] 目录划分是否合理
- [ ] §9.1 字面量预筛方案是否认可（这是性能关键，实现复杂度不低）
- [ ] §10 评分阈值是否认可
- [ ] §11 限速默认值是否认可
- [ ] §12 响应侧检测范围是否认可
- [ ] §15 性能目标是否认可
- [ ] §18 阶段划分与顺序是否认可（P0 骨架是否过轻）
- [ ] §20 未决问题逐条定调

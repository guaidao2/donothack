# Web 控制台设计

> 状态：待评审
> 配套：`docs/DESIGN.md`、`docs/PERFORMANCE.md`、`docs/RULES.md`
> 实现阶段：P5（后端起于 P4）

---

## 1. 定位

donothack 必须有 Web 控制台，用于日常运维：看得见攻击、改得动规则、查得清历史、管得住系统。

**此前"不做 GUI，管理走 API + 命令行"的判断作废。** 生产环境上加一条规则要 SSH 上去改 YAML 再 reload，这不是能用的产品。

控制台的目标不是好看，是**让运维在浏览器里完成 95% 的日常动作**：看攻击态势、查单条事件、启停规则、加白名单、调限速、改配置、看操作记录。

### 本轮范围

- **单站点**：数据面只护一个上游，控制台也只管一个站点。数据结构按多站点预留（`[]Site`），但 P5 不做 Host 路由与多站点切换，多站点后置为 P7。
- 控制台与数据面**同进程、同二进制**，静态资源用 `go:embed`。
- 前端是**原生 ES module SPA，无 Node 构建链**（见 §6）。

---

## 2. 硬约束：控制面与数据面分离

这是控制台设计里唯一不能让步的架构约束。

```
        数据面（每个请求）                    控制面（控制台 + API）
        ─────────────────                    ───────────────────────
   读 atomic.Pointer<Snapshot>            写 control.Apply(newState)
         │                                        │
         │ 只读、不可变、无锁                       │ 校验 → 自测 → 原子替换
         ▼                                        ▼
   ┌──────────────────────────────────────────────────────┐
   │            control（唯一的可变状态入口）              │
   │  Snapshot{ Config, RuleSet, IPLists, Exceptions }     │
   │  atomic.Pointer 发布；旧快照在途请求用完后回收         │
   └──────────────────────────────────────────────────────┘
```

### 2.1 规则

1. **数据面只读不可变快照**，永不阻塞在控制台上。控制台卡住、被扫、崩掉，数据面照常跑。
2. **所有写操作只能走 `control.Apply`**，不允许任何模块直接改配置文件或规则集内存结构。
3. `Apply` 的流程固定：**解析 → 校验 → 内置正负语料自测 → 构造新快照 → 原子替换**。任何一步失败就整体回滚，旧快照继续服务，错误原样回显给控制台。
4. 数据面每条请求在事务开始时**抓一次快照指针**，整个生命周期用它。所以"改到一半"对在途请求不可见。
5. `Apply` 是**串行**的（单写者），用一个 mutex 保护，避免两个运维同时改配置互相覆盖。
6. 控制台**独立监听端口、独立 mux、独立限流**，与数据面监听器完全分开。

```go
// internal/control
type Snapshot struct {
	Config     *config.Config
	Rules      *rules.RuleSet
	IPLists    *iplist.Set
	Exceptions *rules.ExceptionSet
	LoadedAt   time.Time
	Version    string // 内容哈希，进审计
}

type Control interface {
	// Current 数据面用；无锁
	Current() *Snapshot
	// Apply 控制面唯一写入口；串行、失败回滚
	Apply(ctx context.Context, mut Mutation) (*Snapshot, error)
	// Preview 只做应用前的影响预演，不切换
	Preview(ctx context.Context, mut Mutation) (*Diff, error)
	// Subscribe 变更通知（控制台用 SSE 推送）
	Subscribe() (<-chan *Snapshot, func())
}

type Mutation interface {
	Validate(cur *Snapshot) error
	ApplyTo(cur *Snapshot) (*Snapshot, error)
	Actor() string   // 操作审计用
	Describe() string
}
```

`Preview` 是关键能力：**改动前先看到"这次改动会影响多少条规则、哪些请求会从放行变成拦截"**，再点保存。这是"改规则改出事故"的主要防线。

### 2.2 控制台自身的开销上限

控制台在低配机器上最容易翻车的地方是**查询**，不是页面。

| 约束 | 值 |
| --- | --- |
| 事件查询最大时间范围 | 默认 24 小时（可配），超出要求导出 |
| 单页最大行数 | 200 |
| 单次查询服务端超时 | 3s，超时返回部分结果并标注 |
| 查询数据源 | 只允许内存 ring buffer + 最近 N 个日志文件（默认 3 天） |
| 禁止行为 | 全量扫描日志、在请求路径上做聚合、把大结果集一次性序列化 |
| 控制台额外 RSS 预算 | `medium` ≤ 24 MiB，`small` ≤ 8 MiB |
| 静态资源 | embed + 预压缩，`medium`/`large` 走内存缓存；`small` 直接从 embed 读 |

**控制台的流量不进检测引擎**（独立监听器，不过规则），否则会出现"规则把管理员的白名单操作拦了"这种自锁事故。控制台流量也不写入攻击事件，只写操作审计。

---

## 3. 认证与安全

### 3.1 两层：Basic 门槛（挡扫描器）+ 登录（认证）

思路是：**HTTP Basic 挡在最前面，没过 Basic 的请求一律 401，服务器不区分路径是否存在。** 扫描器拿到 401 就走 —— 它既看不到登录页，也探测不出控制台挂在哪个路径、有哪些 API 端点、甚至这是什么产品。过了 Basic 才见到登录页，再走正式认证。

这样"藏路径"就不必再承担安全职责了：Basic 后面的东西对外界是**整体不可见**的。

| 层 | 手段 | 目的 | 是不是安全边界 |
| --- | --- | --- | --- |
| 第一层 门槛 | HTTP Basic | 让扫描器看不到门（登录页、路径、API、产品指纹全部藏在其后） | 否 |
| 第二层 认证 | 表单登录 + 会话 | 回答"你是谁"，授予操作权限 | **是** |

#### 实现细节（这一层最容易写错）

1. **对控制台监听端口上的所有请求统一返回 401，不论路径。** 绝不能写成"只对 `/` 和已知 API 要 Basic，其他路径返回 404" —— 401 与 404 的差异本身就是指纹，扫描器靠这个差异几分钟就能把路径和端点枚举出来。
2. 401 响应**不带 `Server` 头、不带产品特征**；`WWW-Authenticate` 的 realm 用中性字符串（默认 `Restricted`），不要写 `donothack console`。
3. **门槛凭据与登录账号分开**。门槛凭据只解锁登录页，不授予任何操作权限。好处：可以单独轮换、可以给运维同事而不暴露管理口令、泄露了也不等于控制台失守。
4. 门槛失败与登录失败**都计入封禁计数**（见 §3.2）。
5. Basic 通过后浏览器会在每个请求上继续附带凭据，所以第二层的会话 Cookie 仍然必须有 —— 登出、闲置超时、CSRF、操作审计里的 `actor` 全都依赖它。
6. 写操作的 CSRF 防护**不能只靠 Basic**（凭据由浏览器自动附带，跨站表单照样能带上）：必须叠加 CSRF token + 自定义头 `X-Donothack-Console: 1` + Origin 校验。
7. CLI 便利：带合法 `X-Donothack-Token`（`admin.api_token`）的请求可配置为跳过门槛，否则 CLI 每次要同时带两层凭据，太啰嗦。

**可选加密一层**：`gate.path_token` 让控制台挂在随机路径下。因为 Basic 已经挡住了路径暴露，这一层现在只是"顺手便宜"，不是必需；想开就开，成本为零。

**必须启用 TLS**：Basic 凭据是 base64，不是加密。明文公网跑 Basic 等于把门槛口令广播出去。为了不牺牲运维便利，**首次启动若未配置证书，donothack 自动生成自签证书**并打印指纹，浏览器点一次"继续访问"就行；有域名就配真证书或走 ACME。绑非本地地址、既无证书、又没显式 `admin.allow_insecure: true` 时，控制台拒绝启动。

**这个方案的固有代价**：401 本身告诉扫描器"这个端口上有个 HTTP 认证服务"。这是 Basic 门槛换来的必要代价，换来的是登录页、路径、API 与产品指纹全部不暴露 —— 非常划算。想再压低噪音就配非标准端口 + 探测封禁。把边界写清楚，是为了知道它挡什么、不挡什么。

#### 第二层：正式登录

表单登录页 + 会话。配置 `admin.auth_mode`：

| 模式 | 说明 |
| --- | --- |
| `session` | **默认**。表单登录 → 随机 32 字节会话 token 存内存 → Cookie（`HttpOnly; SameSite=Strict; Secure`）+ CSRF token 双提交。可登出、有闲置超时。 |
| `session+basic` | 会话给浏览器；同时接受 HTTP Basic，**只作为 CLI 脚本的便利通道**，不承担认证设计。 |

- 登录失败锁定（见 §3.2）。
- TLS 要求见上（§3.5）。

**技术选型（刻意避开额外依赖）**：

- 口令哈希：标准库 `crypto/pbkdf2`（Go 1.24+ 内置）+ HMAC-SHA256，迭代 600,000（OWASP 建议值），每账号独立随机 salt。**不引 `x/crypto`。** 将来若想上 argon2id，再评估加这一个依赖。
- TOTP 两步验证：标准库 `crypto/hmac` + `encoding/base32` 自己实现，不做依赖。
- 会话：随机 32 字节 token 存内存（带 TTL），Cookie 只放 token。
- 自签证书：启动时用标准库 `crypto/x509` 生成（含 SAN：配置里的域名 + 本机 IP），有效期 1 年，到期前 30 天告警。
- 硬性要求：`admin.password_hash` 为空时**控制台不启动**，启动日志打印生成哈希的命令；`admin.api_token` 供 CLI 与脚本使用，可单独生成与轮换。

### 3.2 登录防护

| 措施 | 值 |
| --- | --- |
| 单 IP 失败上限 | 5 次 → 锁 15 分钟（**门槛失败与登录失败合并计数**） |
| 全局失败上限 | 50 次/分钟 → 全局锁 5 分钟（防分布式喷洒） |
| 登录接口独立限流 | 与控制台静态资源分开计数 |
| 门槛探测封禁 | 同 IP 60 秒内 20 次门槛 401 → 封 15 分钟 |
| 锁定事件 | 写审计 + 指标 `donothack_console_login_locked_total`、`donothack_console_gate_rejected_total` |
| 可选 IP 白名单 | `admin.allow_ips`，默认空（即不限制） |
| 可选 TOTP | `admin.totp_enabled` |
| 会话超时 | 闲置 30 分钟（会话模式） |

### 3.3 应用安全

| 项 | 处置 |
| --- | --- |
| CSP | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'` |
| 内联脚本 | **禁止**。全站外链 ES module，因此 CSP 不需要 `unsafe-inline` 也不需要 nonce。 |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| 版本号 | 登录后才显示；未登录页不泄露版本与构建信息 |
| 错误详情 | 未登录只返回通用错误；登录后返回可诊断信息 |
| DOM 写入 | **只用 `textContent` 与 `createElement`**；`innerHTML` 全站禁用，CI grep 门禁卡死（见 §3.4） |
| 门槛失败 | 同一 IP 60 秒内 20 次 → 封 15 分钟；不返回任何"你被拦了"的细节 |

### 3.4 payload 展示：绝对代码模式

攻击 payload 必须**看得见** —— 看不见就没法判断这是不是误报，运维体验直接垮掉。但它**绝不能作为内容参与 HTML 渲染**。做法是把它当"代码"渲染。

#### 渲染规则（前端唯一通路）

- payload 一律写进 `<pre><code>`，并且**只通过 `textContent` 赋值**，永不经过 `innerHTML`。
- 前端封装唯一原语 `renderCode(text)`：`document.createElement('pre')` + `code.textContent = text`。**所有** payload 展示必须走它，不允许各页面自己拼。
- **全前端禁用** `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `document.write` / `eval` / `new Function`，用 CI 的 grep 门禁卡死（`scripts/lint.py`）。门禁比文档约定可靠 —— 约定会被人忘，门禁不会。
- **不引第三方 markdown 库**。视图结构用自研的极小 markdown 子集渲染器（只支持代码块、表格、粗体、换行），**不支持链接、图片、raw HTML**；代码块内容强制走 `renderCode`。
- payload 文本在**服务端先做可打印化**：控制字符与不可打印字节转 `\xNN`，按 UTF-8 边界截断（默认 4 KiB），并标注是否被截断。这样即使前端出问题，文本里也没有可执行的东西。
- **双层防护**：服务端可打印化 + 前端 `textContent`。任一层失效都不会导致执行。

#### 展示位置

- **列表页只显示摘要**：参数名、算子、命中长度、类目、分数、指纹描述。一屏几十条 payload 展开既刷屏又费带宽。
- **详情页展开代码块**：展示变换前 / 变换后两段 payload（原始与解码后的对比是判断误报的关键信息），复制按钮，以及"下载原始字节"（取证用）。
- 默认仍不落原文：`log.capture_payload` 默认关，审计只记摘要与命中位置。要用代码模式看原文需显式打开抓取，页面提示内存与合规影响。

#### 验收（E2E，必须做）

用三条 payload 走完整链路 —— `<script>alert(1)</script>`、`<img src=x onerror=alert(1)>`、`javascript:alert(1)` —— 断言页面 DOM：

- 没有 `script` 元素被插入；
- 没有任何元素带 `on*` 事件属性；
- 没有任何 `a[href^="javascript:"]`；
- payload 文本出现在 `<pre><code>` 内，且与期望的可打印化结果逐字节一致。

三条都过，这个页面才算做完。

### 3.5 明文绑定与自签证书

因为门槛用的是 HTTP Basic，**TLS 不是可选项** —— Basic 凭据是 base64 编码而非加密。所以：

- **默认路径**：首次启动时若没配证书，donothack 用标准库 `crypto/x509` **自动生成自签证书**（SAN 含配置里的域名与本机 IP），打印证书指纹，浏览器点一次"继续访问"即可。运维便利不打折。
- **有域名**：配真证书，或走 ACME 自动签发（P6 之后再评估）。
- **确实要跑明文**：绑非 `127.0.0.1` 地址、无证书、又没显式写 `admin.allow_insecure: true` —— 控制台**拒绝启动**。显式写 `allow_insecure: true` 时才启动，并打 `level=error` 警告（门槛口令会明文传输）。

理由：这件事可以是运维的决定，但不能是"没注意就发生了"。自签证书已经把"要 TLS"这件事的成本压到几乎为零，剩下的明文场景必须是一次明确选择。

---

## 4. 页面设计

八个页面。每个页面都要在 `small` 档上流畅。

### 4.1 概览

- 请求量 / 拦截量曲线（分钟桶，默认看 1 小时 / 6 小时 / 24 小时）
- 攻击类目分布（SQLi / XSS / RCE / LFI / webshell / 扫描器 / 协议）
- Top 10 攻击源 IP、Top 10 被攻击路径、Top 10 命中规则
- 系统状态卡片：profile、当前与满负载内存、GOMAXPROCS、规则集版本与条数、降级级别、运行时长、上游健康
- 降级状态显眼提示（L1–L4，`block` 模式下降级被拒绝时也要显示"已拒绝降级并返回 503"）

### 4.2 攻击事件

- 列表：时间、客户端 IP、方法、路径、命中规则 ID、类目、分数、裁决、耗时。支持按时间/裁决/类目/规则/IP/路径过滤。**列表只显示摘要，不展开 payload。**
- 详情：事务全链路 —— 每个命中的 target（参数名）、变换链、**变换前后 payload 两块代码块**（走 §3.4 的 `renderCode`）、算子与判定结果、分数累计过程、最终裁决来源、上游耗时、`ruleset_version`。
- 实时：SSE 推送新事件，页面顶部可开关。
- 导出：CSV / JSONL（payload 字段为可打印化后的文本），导出走的还是同一个有界查询。
- 取证：详情页可"下载原始字节"，用于需要逐字节分析的场景。

### 4.3 规则管理

- 规则集列表，按文件 / 类目 / 严重度 / 开关状态筛选
- 单条规则抽屉：YAML 原文、命中统计（来自 `donothack_rule_hits_total`）、正负样本、启停开关
- 启停不是改文件，而是生成一个 `Mutation`（覆盖层），走 `control.Apply`
- 新增/编辑自定义规则：YAML 编辑器 + **保存前强制校验**（语法、算子名、字面量长度、正负样本是否满足 §RULES 9.2 的硬约束）

### 4.4 规则测试台

把一条真实原始请求粘进去（HTTP 报文文本框或 cURL 命令），直接看到完整命中链路：

```
phase1 ───────────────────────────────────
  (无命中)
phase2 ───────────────────────────────────
  SQLI-942100   ARGS:user
    transforms: removeComments,urlDecode,compressWhitespace,lowercase
    before: admin'/**/UNION/**/SELECT/**/1,2--
    after:  admin' union select 1,2--
    operator: detectSQLi → MATCH (fingerprint: union select)
    score: +5 (sqli) → total 5
verdict: BLOCK (threshold 5, mode block)
```

调误报时这是最有用的一个页面。后端与 CLI `donothack test -r` **共用同一个实现**。

### 4.5 例外与白名单

- IP 黑白名单（CIDR，带备注与过期时间）
- 路径例外、规则例外（与 `docs/RULES.md` §8 的例外结构一一对应）
- **强制字段**：`reason` 与 `expires`。到期自动失效并在页面显著提示，防止"临时例外变永久后门"。
- 展示每条例外最近的命中次数 —— 一条从来不命中的例外就是该删的。

### 4.6 CC 防护与限速

- 全局与按路径/按 IP 的阈值配置
- 当前封禁列表（IP、封禁原因、剩余时间），支持手动解封
- 状态表容量与当前使用量（`ratelimit_table_capacity`），接近上限时告警
- 白名单直通

### 4.7 系统设置

- 门槛：开关与 realm、**门槛凭据设置与一键轮换**（旧凭据立即失效）、门槛失败统计与封禁列表、可选随机路径开关、自签证书查看与重新生成
- 认证：登录口令修改、TOTP 绑定（二维码用纯 JS 生成，本地渲染）、会话超时、`api_token` 生成与轮换
- 通知：webhook 地址、测试按钮、告警规则（拦截激增、规则加载失败、上游不可用、降级触发）
- 日志：保留天数、单文件大小、payload 抓取开关（**打开时会显著警告内存与合规影响**）
- 配置：当前配置只读视图、编辑（走 `Preview` → `Apply`）、与运行中的差异对比、导入/导出
- 备份：一键导出配置 + 规则集 + 名单为单个 tar.gz；导入前强制 `Preview`
- 版本信息、构建时间、profile 预算表

### 4.8 操作审计

与控制台分离的一条流，记"谁在什么时候改了什么"：

```json
{
  "ts": "2026-10-06T12:00:00Z",
  "actor": "admin",
  "src_ip": "203.0.113.7",
  "action": "rules.disable",
  "target": "SQLI-942100",
  "result": "ok",
  "diff": {"enabled": [true, false]},
  "ruleset_version_before": "sha256:…",
  "ruleset_version_after": "sha256:…"
}
```

规则库被改动却查不到，比规则被绕过更难看。

---

## 5. API（控制台与 CLI 的唯一入口）

`/api/v1/`，JSON。CLI `donothackctl` 与控制台走同一套，**不允许两套逻辑**。

| 分组 | 端点 |
| --- | --- |
| 认证 | `POST /login`、`POST /logout`、`GET /session`、`POST /password`、`POST /totp/enroll` |
| 门槛 | `GET /gate`（当前门槛配置与凭据状态）、`POST /gate/rotate`（轮换门槛凭据，旧凭据立即失效）、`POST /gate/path/rotate`（若启用随机路径，重新生成）、`POST /gate/cert/selfsigned`（重新生成自签证书） |
| 状态 | `GET /status`（版本、profile、内存预算、降级级别、运行时长、规则集版本） |
| 指标 | `GET /metrics/summary`、`GET /metrics/timeseries?range=1h` |
| 事件 | `GET /events`、`GET /events/:id`、`GET /events/:id/raw`（原始字节，取证用）、`GET /events/stream`（SSE）、`GET /events/export` |
| 规则 | `GET /rules`、`GET /rules/:id`、`PATCH /rules/:id`（启停）、`POST /rules/validate`、`POST /rules/test`、`GET /rulesets` |
| 规则集操作 | `POST /rulesets/reload`、`POST /rulesets/preview` |
| 例外 | `GET/POST/PATCH/DELETE /exceptions`、`GET/POST/DELETE /ip-lists` |
| 限速 | `GET /ratelimit`、`PUT /ratelimit`、`GET /bans`、`DELETE /bans/:ip` |
| 配置 | `GET /config`、`PUT /config`（带 `Preview`）、`GET /config/diff`、`POST /config/reload` |
| 备份 | `GET /backup`（下载）、`POST /restore`（先 `Preview`） |
| 通知 | `GET/PUT /notify`、`POST /notify/test` |
| 操作审计 | `GET /console-audit` |

约定：

- 写操作一律 `POST`/`PUT`/`PATCH`/`DELETE` + 自定义头 + Origin 校验。
- 所有写操作返回 `{ok, snapshot_version, warnings[]}`；`warnings` 用于"这次改动的副作用"提示。
- 错误统一 `{error: {code, message, detail}}`，`code` 稳定可编程判断。
- 分页 `?limit=200&cursor=…`，不用 offset（避免深分页扫表）。

---

## 6. 前端：原生 ES module SPA，无构建链

要求是"现代、前后端分离、但不用起 Node"。落地方式：

```
web/
  index.html                 唯一 HTML 外壳（外链脚本，无内联）
  assets/
    app.js                   启动、路由注册、布局
    router.js                History API 路由（约 60 行）
    api.js                   fetch 封装、统一错误与认证头
    store.js                 轻量响应式状态（约 80 行，手写，不引框架）
    dom.js                   模板字面量 helper + **renderCode 原语**（约 60 行）
    md.js                    极小 markdown 子集渲染器（代码块/表格/粗体/换行，约 80 行）
    safe.js                  禁止清单的运行时断言（开发模式下 innerHTML 被改写为抛错）
    views/dashboard.js
    views/events.js
    views/rules.js
    views/ruletest.js
    views/exceptions.js
    views/ratelimit.js
    views/settings.js
    views/audit.js
    components/table.js  chart.js  drawer.js  toast.js  modal.js
    vendor/uplot.min.js      ~40 KB（MIT），图表
    vendor/uplot.min.css
    styles/tokens.css        设计变量（色板、间距、字号）
    styles/base.css
    styles/components.css
```

技术要点：

- **原生 ES module**：浏览器直接 `import`，不需要打包器。所有文件走 `go:embed`，由 Go 静态文件服务发出，MIME 类型正确即可。
- **无 TypeScript、无 JSX**：视图用模板字面量 + 一个 `dom.js` helper（插值走 `textContent`，不做字符串拼 HTML）。
- **不用框架**：状态管理手写约 80 行（对象 + 订阅 + 重渲染），SPA 复杂度在这个规模下不值得引框架。
- **`innerHTML` 全面禁用**：所有 DOM 写入只走 `createElement` + `textContent`。payload 走 `renderCode`（见 §3.4），结构文本走 `md.js`。CI 门禁 `scripts/lint.py` grep 全前端源码，命中即失败；开发模式下 `safe.js` 把 `innerHTML` 改写成抛错，本地一跑就炸，不用等 CI。
- **markdown 只用于"结构"，不用于"内容"**：`md.js` 只支持代码块、表格、粗体、换行四种子集，不支持链接、图片、raw HTML、内联事件。代码块内容强制 `textContent`。**不引任何第三方 markdown 库** —— 引进来就等于把渲染器的 XSS 面一起引进控制台。
- **图表用 uPlot**（40KB，无依赖，性能好，低配浏览器也不卡）。
- **路由**：门槛路径前缀下全部回落到 `index.html`；`/api/v1/*` 走 API。
- **缓存**：带内容哈希的资源 `Cache-Control: public, max-age=31536000, immutable`；`index.html` `no-cache`。资源 URL 带 `?v=<build>`，构建版本来自 `ldflags` 注入的版本号，所以**不需要构建链也能做缓存失效**。
- **预压缩**：CSS/JS 在仓库里存 `.gz` 或启动时首次请求压缩后缓存；`small` 档只做流式 gzip，不常驻。

体积预算：vendored uPlot 40KB + 自写 JS ≤ 140KB + CSS ≤ 40KB ≈ **220KB 未压缩，gzip 后约 65KB**。二进制目标 ≤ 14 MiB。

界面风格：手写 design tokens，深浅色主题跟随系统，表格与抽屉为主，不追求花哨动效 —— 运维页面要的是信息密度和响应速度。

---

## 7. 事件存储

三层，按"贵不贵"分层，避免在低配上引外部数据库。

| 层 | 内容 | 容量（`medium`） | 用途 |
| --- | --- | --- | --- |
| 热 | 内存 ring buffer（命中事件） | 1024 条 | 事件列表、SSE 实时、详情 |
| 温 | 分钟级聚合桶 | 1440 个（24h） | 曲线、Top N |
| 冷 | 按天 JSONL 审计文件 + 轻量偏移索引 | 按保留策略 | 历史查询、导出 |
| 可选 | 纯 Go SQLite（`modernc.org/sqlite`，无 CGO） | 关闭 | 富查询；`small`/`medium` 默认关 |

- **保留策略**：按天数（默认 7 天）+ 总大小（默认 512 MiB）双限，超限删最旧，删除动作记操作审计。
- **不引 InfluxDB / Elasticsearch / ClickHouse**：2 核 2G 上跑不动，也没必要。
- 冷层查询只扫最近 N 天（默认 3 天）的文件，配合偏移索引按时间定位，不做全量扫描。
- 聚合桶在内存里是定长数组（1440 × 小结构），约 100KB，**不随流量增长**。

---

## 8. 数据流（改一条规则）

1. 控制台提交 `PATCH /rules/SQLI-942100 {enabled:false}`。
2. 后端构造 `Mutation`，`control.Apply` 串行执行。
3. **校验**：规则 ID 存在、YAML 合法、算子与变换名已注册。
4. **自测**：内置正负语料跑一遍，确认没把别的规则带坏。
5. **`Preview`**（写操作前可选）：算出这次改动的影响 —— 受影响规则数、快照版本变化。
6. **构造新快照**：拷贝旧快照 + 应用覆盖层，规则集重新编译并重建预筛自动机。
7. **原子替换** `atomic.Pointer`；在途请求继续用旧快照，新请求用新快照。
8. **操作审计**落盘，SSE 通知所有已登录控制台。
9. 旧快照引用计数归零后回收（或交给 GC）。

任何一步出错：**不替换**，返回错误给页面，线上维持原状。

---

## 9. 资源预算（`medium` 档）

| 项 | 预算 |
| --- | --- |
| 控制台额外常驻内存 | ≤ 24 MiB（含聚合桶、ring buffer、会话表、静态资源缓存） |
| `small` 档 | ≤ 8 MiB |
| API 单请求 CPU | ≤ 2ms（除导出） |
| 事件查询延迟 | P99 < 300ms（3 天范围内） |
| 静态资源首屏 | gzip 后 ≤ 60KB |
| 二进制体积 | ≤ 14 MiB（含控制台资源，strip 后） |

控制台**不参与**数据面性能门禁的延迟统计，但它的内存计入总预算，超了要报错而不是慢慢涨。

---

## 10. 阶段与验收

### P4 运维后端（控制台的前提）

- `internal/control`：`Snapshot`、`Apply`、`Preview`、`Subscribe`；单写者串行；失败回滚
- `internal/audit`：JSONL + 轮转 + ring buffer + 分钟聚合桶 + 有界队列丢弃计数
- `internal/admin`：完整 `/api/v1`（除页面相关）、认证（basic/session/both）、失败锁定、CSRF、操作审计
- 验收：reload 零失败请求；`Apply` 失败时线上状态不变且错误可诊断；伪造 Origin/缺自定义头的写操作被拒；5 次失败后锁定生效

### P5 Web 控制台

- `web/` 前端 + `go:embed` + 静态服务（缓存、gzip、CSP 头）
- 八个页面全部可用
- 验收：`small` 档页面可用且控制台额外内存 ≤ 8 MiB；事件查询 3 天范围 P99 < 300ms；**payload 原文不出现在任何列表页**（用一条含 `<script>` 的 payload 做验证）；CSP 无 `unsafe-inline`；公网明文绑定必须显式 `allow_insecure` 才能启动

### P6 规则集与投产（原 P5 后移）

- 全类目规则集、误报治理报告、真机基线、运维手册、发布流程

### P7 多站点（后置）

- 数据面按 Host 路由到不同上游与规则集、站点级证书与开关、控制台站点管理页
- 届时 `Snapshot` 从单站点扩为 `[]Site`，控制台增加站点切换器

---

## 11. 待确认

- [x] 单站点先行，多站点 P7（2026-10-06 定）
- [x] 前端原生 ES module SPA，无 Node 构建链（2026-10-06 定）
- [x] 控制台可公网访问（2026-10-06 定），因此 TLS、失败锁定、自定义头 + Origin 校验为**强制项**
- [x] 准入分两层：**第一层 HTTP Basic 门槛**（未过则一切路径统一 401，登录页/路径/API/产品指纹全部藏在其后）+ **第二层表单登录认证**（`auth_mode` 默认 `session`）。门槛凭据与登录账号分开；门槛不是安全边界，认证才是
- [x] 因门槛用 Basic，**TLS 强制**；未配证书时首次启动自动生成自签证书（标准库 `crypto/x509`），明文绑定需显式 `admin.allow_insecure: true`
- [x] payload 展示用**绝对代码模式**：`<pre><code>` + `textContent`，`innerHTML` 全站禁用并加 CI 门禁，不用第三方 markdown 库（见 §3.4）
- [ ] 是否需要多用户与角色（管理员 / 只读运维）——当前设计为单管理员 + 只读 API token
- [ ] 事件保留默认 7 天 / 512 MiB 是否合适
- [ ] 是否需要随机路径这层额外遮挡（Basic 已挡住路径暴露，此层只是顺手便宜）
- [ ] 控制台是否需要支持暗色以外的主题定制（暂定跟随系统）

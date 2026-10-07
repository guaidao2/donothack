# donothack

**请求侧 Web 应用防火墙。** 单二进制、无 CGO、无外部依赖（只用 Go 标准库 + `yaml.v3`），
以反向代理形态部署在业务服务之前：检查请求的头、体与参数里有没有攻击 payload，
响应不检测、不缓冲、不修改，原样流式透传。

作者：**guaidao2 & coolmoon** · 模块路径 `donothack` · 二进制名 `donothack`

**许可：[donothack 许可 v1.0](LICENSE) —— 自用免费，禁止转售。**
自己用、自己改、免费给别人用都可以；拿它赚钱要先谈授权。用途对照见文末[许可](#许可)。

---

## 1. 它解决什么问题

大多数自建 WAF 的部署门槛是"先给我几个 G 内存"。这个项目的前提反过来：
**一台 1 vCPU / 512 MiB 的 VPS 也要跑得动，而且不能因为 WAF 本身把业务拖死。**

由此定下三条硬约束，实现里到处能看到它们的影子：

- **热路径零分配是门禁，不是优化目标。** `BenchmarkEngine_NoMatch` 必须 0 allocs/op，
 超标即构建失败。核少的机器上 GC 是主要 CPU 开销，省下的分配直接变成吞吐。
- **每一项资源都有上限** —— 请求体、连接数、参数个数、限速表容量、日志体积。
 无界即漏洞：伪造源 IP 喷一遍就能把内存打爆。
- **fail-open 但不静默。** 解析或规则出任何异常都放行（WAF 绝不能成为业务单点故障），
 但每条异常都会记分并在控制台可见。绝不出现"看起来在防护，其实什么都没检查"。

## 2. 能做什么，不做什么

**能做的：**

| 能力 | 说明 |
| --- | --- |
| 请求侧检测 | SQL 注入、XSS、命令注入、路径穿越、文件包含、Webshell 上传、扫描器指纹、协议违规，出厂 60 条规则 / 9 个文件 |
| 反绕过解析 | query / form / JSON / XML / multipart / cookie / header 统一拆平成扁平命名空间；路径规范化、HPP、值级编码文档（JSON、base64(JSON)）逐字段展开后再匹配 |
| 评分制裁决 | 按类目累积分，达阈值才拦。三种模式：`detect` 只记、`block` 拦、`mixed` 按类目分别设阈值 |
| 防护动作 | 拦截页（按 Accept 自适应 HTML / JSON / 纯文本）、限速、封禁、Drop、Tarpit |
| 过载降级 | L0–L4 分级；`block` 模式只允许 L1，再往上返回 503 而**不是**悄悄放行 |
| Web 控制台 | 总览与降级状态、事件检索与导出、规则启停与测试台、例外、IP 名单、限速、配置差异与热重载、告警通道、备份、操作审计、TOTP 两步验证 |
| 热改配置 | 引擎模式与阈值、限速、拦截页、规则集都能运行期原子替换；无效改动整批拒绝并回滚 |
| 可观测 | `/healthz`、`/readyz`（含降级与日志状态）、访问日志、事件环形缓冲、类目统计、webhook 告警 |

**不做的（明确的边界）：**

- **不做响应侧检测。** 不检查响应体里有没有敏感信息泄漏，也不看状态码。攻击是否成功由上游决定，
 本产品只判断"这个请求像不像攻击"。
- 不做多站点 / 证书编排 / 负载均衡 / DDoS 清洗 / CDN / 威胁情报协同。
- 不引外部数据库、不引 PCRE、不引 Node 构建链。控制台是原生 ES module SPA，
 前端产物 `go:embed` 进二进制，交付就是一个文件。
- **不承诺拦截所有攻击。** 请求侧信息不足的形态只记分不拦，例如"把参数当表达式求值"的裸算术探测
 `a=1999*1999` —— 因为 `?resolution=1920*1080` 长得一模一样，拦它换来的误报比收益贵得多。

## 3. 快速上手

```bash
# 编译（无 CGO；GOAMD64 必须是 v1 —— 低配 VPS 的 CPU 常不支持 AVX2，
# 用默认的 v3 编译出来会直接 illegal instruction 崩掉）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
 go build -trimpath -ldflags="-s -w" -o dist/donothack ./cmd/donothack

# 看当前档位与内存预算（不启动服务）
./dist/donothack -c config.example.yaml -print-budget

# 生成控制台登录口令的哈希
./dist/donothack hash-password    # 交互输入；或 echo -n '口令' | donothack hash-password

# 起服务
./dist/donothack -c config.yaml
```

最小可用配置（其余全用默认值）：

```yaml
upstream:
 url: "http://127.0.0.1:9000"   # 你的业务服务
engine:
 mode: detect           # 第一次先 detect：只记录，不拦
```

三件容易漏的事：

1. **`profile` 先确认。** `-print-budget` 会打印探测到的档位与来源
  （cgroup v2 → cgroup v1 → `/proc/meminfo` → `NumCPU`）。容器里没挂 cgroup 时探测会不准，
  直接在配置里写死 `profile: medium`。
2. **站点前面有 nginx / CDN 时，`real_ip.trusted_proxies` 必须配准。**
  留空的话所有请求的来源 IP 都是代理地址 —— 限速对所有用户共用一个桶、封禁一封封一片、
  日志里的来源 IP 全是代理地址。配错（把公网网段写进去）则攻击者伪造 `X-Forwarded-For`
  就能自称任意 IP，限速与封禁被完全绕过。
3. **第一次上线用 `engine.mode: detect`。** 拦截规则是否误伤业务只有真实流量说了算。
  `detect` 下所有命中都进事件与控制台，先看"哪些会被拦、拦得对不对"，确认后再切 `block`。

### 做成系统服务

```ini
# /etc/systemd/system/donothack.service
[Unit]
Description=donothack WAF
After=network-online.target

[Service]
Type=simple
User=donothack
WorkingDirectory=/opt/donothack
ExecStart=/opt/donothack/donothack -c /opt/donothack/config.yaml
# 日志交 journald（比自写轮转省 CPU 与磁盘）；要用文件轮转就把配置里 log.output 改成 file
StandardOutput=journal
StandardError=journal
Restart=on-failure
RestartSec=3
MemoryMax=1536M     # 给 Go 一个明确的内存天花板，避免被 OOM 杀掉
TimeoutStopSec=30    # 优雅停机：停止接受新连接，把在途请求做完

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now donothack
journalctl -u donothack -f
```

## 4. 配置

**逐项参考是仓库根的 [config.example.yaml](config.example.yaml)** —— 它每行都有注释，
而且是**真正被解析的那份文件**，不会和实现漂移。下面只说必须理解的部分。

两条贯穿全篇的约定：

- **未知字段会让启动失败。** 解析器开了严格模式，名字写错、字段被废弃都会在启动时
 直接报错并指出行号。这是刻意的：WAF 配置里"写了但没生效"是最难查的一类故障。
- **可以运行期改的字段**（改完走 `POST /config/reload`，控制台"设置 → 配置"里也有按钮）
 只有这些：`engine.mode`、`engine.inbound_anomaly_threshold`、`engine.category_thresholds`、
 `engine.ban_on_block`、`engine.block_ban_duration`、`ratelimit.*`、`block_page.*`、
 `rules.dir`、`rules.files`、`rules.self_test`。**其余一律需要重启进程。**
 `GET /config/diff` 可以先看"磁盘上的配置和正在跑的有哪些差异、哪些能热改"。

### 4.1 必须理解的几项

| 配置 | 默认 | 要点 |
| --- | --- | --- |
| `profile` | `auto` | 决定一堆上限与 GC 参数（见 5.1） |
| `upstream.allowed_hosts` | `[]` | Host 头白名单，支持 `*.example.com`。**留空 = 不校验**。应用若回显 Host，不开就会产生 Host 头注入类问题（密码重置链接指向攻击者域名）——这是 WAF 侧唯一能主动收口的一招 |
| `real_ip.trusted_proxies` | `[]` | 见上一节。留空时完全忽略 `X-Forwarded-For` |
| `engine.mode` | `detect` | 见 4.2 |
| `engine.inbound_anomaly_threshold` | `5` | 总分达到它就拦 |
| `engine.ban_on_block` | `false` | 判定拦截时顺带封禁来源。**建议先别开**：封禁是加码动作，误判时影响的是一个来源的一段时间，等误报率确认后再开 |
| `ratelimit.*` | 见示例 | 限速与封禁返回 429（不是 `block_page.status`），带 `Retry-After` |
| `log.access_mode` | `all` | 切到 `block` 之后建议改成 `hit`（只记非 pass），否则高 QPS 下日志会吃满磁盘 |
| `log.min_free_mb` | `1024` | 磁盘剩余低于它就**丢弃日志**并计数 —— 它优先于日志完整性 |
| `admin.password_hash` | `""` | 用 `donothack hash-password` 生成。留空则每次启动随机生成一个并打印 |
| `admin.allow_ips` | `[]` | 控制台的来源白名单。**留空 = 不限制**；填了就是硬边界，CLI 所在机器也要写进来 |
| `admin.max_login_fails` | `5` | 登录失败次数上限，超过就封该来源（`admin.lockout`，默认 15 分钟） |
| `alert.webhook` | `""` | 告警通道；默认禁止指向内网地址（防 SSRF），内网网关需 `alert.allow_private_hosts: true` |

### 4.2 三种运行模式

- `detect` —— **首次上线必须从这里开始**。任何命中都只记录。
- `block` —— 总分 ≥ `inbound_anomaly_threshold` 就拦。
- `mixed` —— 按类目分别设阈值，例如"SQL 注入 3 分就拦，扫描器指纹 20 分才拦"：

 ```yaml
 engine:
  mode: mixed
  category_thresholds:
   sqli: 3
   rce: 3
   scanner: 20
 ```

 没配的类目回落到 `inbound_anomaly_threshold`；多个类目同时命中时任一类达标就拦。
 配置校验会强制两件事：`mixed` 必须配 `category_thresholds`（否则它和 `block` 完全一样），
 非 `mixed` 模式不许配（否则你以为生效了）。

### 4.3 控制台准入

控制台默认 `admin.addr: 127.0.0.1:9443` + `admin.tls.enabled: true` + 自签证书。

准入只有一层：**表单登录 + 会话**，用户名 `admin`、口令是 `admin.password_hash`
（留空则每次启动生成一个随机口令并在日志里打印一次）。

- 写操作（改口令、TOTP、规则启停、切模式、保存限速等）必须带 `X-Donothack-Console: 1`
  头 + CSRF 令牌 + Origin 同源 —— 只靠 cookie 挡不住跨站表单。
- 会话有 30 分钟闲置超时与 **12 小时绝对上限**（滑动不越过它）。
- 登录失败按 `admin.max_login_fails`（默认 5 次 / 15 分钟窗口 → 封 15 分钟）封来源。
- 想限制谁能连这个端口，用 `admin.allow_ips`（支持 CIDR）；它是网络边界，
  对所有人一视同仁，**CLI 所在机器也要写进去**。

> 早期版本在这个端口上还叠了一层 HTTP Basic「门槛」。它只是遮挡、不是认证边界，
> 却让运维多记一套凭据、还要面对浏览器反复弹窗，现在已移除。老配置里如果还留着
> `admin.gate:`，启动会直接告诉你把整段删掉。

两种起法：

- **只给本机用**（推荐）：保持 `127.0.0.1`，`ssh -L 9443:127.0.0.1:9443 you@vps`，
  浏览器开 `https://127.0.0.1:9443/`，接受自签证书。
- **要公开访问**：改 `admin.addr` 为 `0.0.0.0:9443`，**并且换掉自签证书**改配真证书、
  设 `auto_self_signed: false`，防火墙只放你要的源 IP。

### 4.4 保护 Docker 应用映射出来的端口

常见情形：应用跑在 Docker 里，用 `-p 8080:80` 把端口映射到宿主机对外服务，
现在想在它前面加一道 WAF。**donothack 直接跑在宿主机上**（二进制 + systemd，见第 3 节），
不参与容器编排。

要做的只有两步，顺序不能反。

**第一步：把应用的映射改成只绑回环。** 这一步是成败关键 —— 只要 `8080` 还挂在
`0.0.0.0` 上，攻击者绕过 WAF 直连它就完事了，WAF 只是个摆设。

```yaml
# compose.yaml
services:
  web:
    image: your-app:latest
    ports:
      - "127.0.0.1:8080:80"        # 只绑回环：外部访问不到，WAF 能访问
```

命令行起容器的写法等价：`docker run -p 127.0.0.1:8080:80 your-app`。

**第二步：让 donothack 指向它，并对外监听 80。**

```yaml
listen:
  addr: "0.0.0.0:80"               # WAF 是对外那一个

upstream:
  url: "http://127.0.0.1:8080"     # 指回宿主机的回环，就是那个容器
  allowed_hosts: ["your-domain.com", "*.your-domain.com"]

engine:
  mode: detect                     # 先观察，确认误报后再切 block（控制台里可热切）

log:
  dir: "/var/log/donothack"
  access_mode: all

admin:
  addr: "127.0.0.1:9443"           # 控制台只给本机，SSH 隧道访问
  tls:
    enabled: true
    auto_self_signed: true
```

**验证（两条都要过）**：

```bash
# 1. 正常请求应当经由 WAF —— 响应里会有 X-Donothack-* 头，并被记进日志
curl -sI -H 'Host: your-domain.com' http://<服务器公网IP>/ | head -20

# 2. 直连应用端口必须连不上（这一步证明绕不过去）
curl -sI --max-time 3 http://<服务器公网IP>:8080/    # 期望：连接被拒
```

如果第二条还能通，说明容器还在对外映射，回第一步。

几条容易踩的：

- **Docker 的端口映射会绕过 ufw / firewalld 的 INPUT 规则**（它走 DNAT 链）。
  所以"用防火墙挡住 8080"通常不管用；`-p 127.0.0.1:8080:80` 才是可靠做法。
  真要按源 IP 收口，规则得写进 `DOCKER-USER` 链。
- **donothack 是唯一入口时不需要配 `real_ip.trusted_proxies`** —— 它看到的就是
  客户端真实 IP，限速与封禁按这个记。只有当它前面还有一层反代或 CDN
  （Nginx、Traefik、Cloudflare）时才需要，见 4.1 与下一节。
- **容器之间互相调用不受影响**：别的容器用服务名或容器 IP 访问应用，不经过宿主机映射。
- **别把控制台端口 `-p` 出去**：`admin.addr` 保持 `127.0.0.1:9443`，远程用
  `ssh -L 9443:127.0.0.1:9443 you@host`。
- **应用自己也该改回 `network_mode: host` 吗？** 不需要。保持默认 bridge 网络 +
  `127.0.0.1` 映射最简单；`network_mode: host` 会让容器直接占用宿主机端口，
  反而更难和 WAF 分工。
- **TLS 终结在 WAF 上**：证书配在 donothack（`listen.tls.*`），容器里的应用继续跑明文 HTTP，
  少一份证书要维护。

### 4.5 前面还有一层反代或 CDN

donothack 前面挂着 Nginx、Traefik 或 Cloudflare 时，它看到的来源 IP 会变成那一层，
限速、封禁、攻击事件里的来源都会失真。这时必须配：

```yaml
real_ip:
  header: "X-Forwarded-For"        # Cloudflare 用 "CF-Connecting-IP"
  trusted_proxies:                 # 只信这些来源发来的那个头
    - "172.16.0.0/12"
    - "127.0.0.1/32"
```

`trusted_proxies` 留空时 `X-Forwarded-For` 会被**完全忽略**（这是刻意的：随便信任这个头
等于让攻击者自由伪造来源）。只填你确实控制的那几段 —— 填 `0.0.0.0/0` 就等于放弃来源判断。

## 5. 性能与容量

### 5.1 档位

| profile | 适用 | vCPU | 内存 | `max_inspect_body` | `max_conns` | `max_rules` | 吞吐目标 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `small` | 最小 VPS | 1 | 512 MiB | 128 KiB | 256 | 400 | 3000 rps |
| `medium` | 目标档 | 2 | 2 GiB | 512 KiB | 1024 | 2000 | 8000 rps |
| `large` | 独立服务器 | 4+ | 4 GiB+ | 1 MiB | 4096 | 10000 | 20000 rps |
| `auto`（默认） | — | — | — | 按 cgroup 自动探测，探测不到时用 `NumCPU` + 保守默认并打印来源 | | | |

档位还决定 `max_idle_conns_per_host`、`max_prefilter_literals`、`ring_buffer_size`、
`ratelimit_table_capacity`、控制台内存预算、`GOGC` 与 `GOMEMLIMIT` 比例。
`-print-budget` 打印完整分解（规则集 + AC 自动机、预筛、并发连接 × 每连接预算、
事务池、限速表、事件缓冲、控制台、运行时），总账就是它。

### 5.2 本机实测

Windows 11 / 24 核 / 16 GiB，`medium` 档，32 并发 10 秒。
**基线是"裸反向代理"**（同样的连接池调优、不做检测）—— 直连上游只有一跳，
拿它当基线量出来的是"多了一跳"的成本，不是 WAF 的开销。

| 指标 | 直连上游 | 裸反向代理 | donothack |
| --- | --- | --- | --- |
| RPS | 89616 | 27429 | **35332** |
| P50 | 0.485 ms | 1.081 ms | **1.049 ms** |
| P99 | 1.580 ms | 3.225 ms | **2.288 ms** |
| 常驻内存 | — | — | **44.2 MiB** |
| 非 2xx / 错误 | 0 | 0 | 0 |

这些是**本机数字，不是 VPS 基线**。真机基线要在一台目标档 VPS 上实跑一次才算数，
方法见 `scripts/bench.py`（它会同时压直连、裸代理与 donothack 三者并生成报告）。
不要拿本机数字承诺容量。

### 5.3 门禁与验证

提交前跑 `python scripts/lint.py`，必须全绿：格式、`go vet`、全部单测、
前端 DOM 写入禁令、emoji 禁令、embed 一致性、**热路径零分配**
（`BenchmarkEngine_NoMatch` = 4231 ns/op、0 B/op、**0 allocs/op**）。

功能验证：

| 项目 | 命令 | 结果 |
| --- | --- | --- |
| 请求语料 | `python scripts/acceptance.py --waf 127.0.0.1:18080 --corpus testdata/corpus` | 26/26 必拦被拦、18/18 必放放行、3/3 弱信号只记分 |
| 透传保真度 | `python scripts/passthrough.py --direct <上游> --waf <donothack>` | 6/6 一致（代理不改动上游语义） |
| 控制台端到端 | `python scripts/verify_notify_totp.py` | 25/25 |
| 主动注入扫描 | `python scripts/active_check.py`（约 4 秒，6 个端点） | 残余 1 条：裸算术 SSTI，见第 2 节 |

## 6. 日常运维

### 6.1 健康检查

| 端点 | 用途 |
| --- | --- |
| `GET /healthz` | 存活。进程还在、HTTP 栈能响应 |
| `GET /readyz` | 就绪。返回 `status` / `profile` / `ruleset` / `upstream` / `degrade` / `log` |

**把 `/readyz` 接进探针，别接 `/healthz`** —— 存活探针在降级时仍应返回 200，
否则会被反复重启。`/readyz` 里几个关键字段：

- `degrade.level`（数字，0 = 正常）、`level_name`、`reason`、`inflight`、`transitions`
- `log.dropped` 持续增长 → 磁盘水位触发了丢日志，**这比看起来严重**，先清盘
- `upstream.ok: false` → 上游连不上，客户端会收到 502

### 6.2 过载降级（最需要理解的一节）

低配机上 **WAF 自己成为瓶颈比"少拦几条"危险得多**，所以有过载保护，
而且它宁可返回 503 也不静默少检测。判定依据是 **GC CPU 占比**
（Go 的 GC pacer 默认目标就是 25%，所以 0.2 上下是**正常水平**，不是过载）。

| 档位 | 行为 | 进入阈值 |
| --- | --- | --- |
| L0 正常 | 什么都做 | GC CPU < 35% |
| L1 丢日志 | 停止写访问日志（计数照记），**检测完全不变** | ≥ 35% |
| L2 跳昂贵算子 | 跳过语义算子（`detectSQLi`/`detectXSS`/`entropy`）与长变换链 | ≥ 50% |
| L3 只跑阶段 1 | 不看请求体，只查请求头与 URL | ≥ 65% |
| L4 旁路 | 完全不过规则，只做转发 | ≥ 80% |

**模式决定降级到哪一档**：`detect` 在 L2+ 是**旁路**（反正本来就不拦，不如把 CPU 省下来）；
`block` / `mixed` 在 L2+ 一律返回 **503**（`X-Donothack-Reject: degrade`）——
拦截模式下"检测能力下降但不告诉你"是不可接受的，宁可让流量去别处。

恢复用滞回（退出阈值低于进入阈值），避免在阈值附近来回抖。降级状态在三处可见：
应用日志、`/readyz`、控制台顶部横幅。

### 6.3 日志与磁盘

日志去向二选一：交 journald（`log.output: stdout`，推荐）或用内置文件轮转
（`log.output: file`）。别两边都存。

文件轮转有**三道闸**，按优先级：

1. `min_free_mb`（默认 1024）—— 磁盘剩余低于它就丢弃日志并计数。
  **它优先于日志完整性**：日志价值远低于业务可用性，盘写满会连带拖死业务与系统服务。
2. `total_max_mb`（默认 512）—— 日志目录硬顶，**含正在写的文件**（同目录多条日志共用一份配额），
  超了删最旧的。
3. `max_size_mb` × `max_backups` —— 单文件大小与份数。

访问日志策略：`all` 全记（刚上线、还在 detect 时用）、`hit` 只记非 pass（**切 block 后推荐**）、
`sample` 非 pass 全记 + pass 按比例采样。实测 29k rps 全量记录约 **22 MB/s**，
20 GB 盘十几分钟写满。轮转后异步 gzip，压不过来就跳过并计数，绝不阻塞写。

### 6.4 容量规划

| 机器 | 档位 | 预期 | 磁盘（日志） |
| --- | --- | --- | --- |
| 1 vCPU / 512 MiB | `small` | ≥ 3000 rps，满负载 < 48 MiB | ≥ 2 GB，`total_max_mb: 128` |
| 2 vCPU / 2 GiB | `medium` | ≥ 8000 rps，满负载 < 120 MiB | ≥ 5 GB，`total_max_mb: 512` |
| 4+ vCPU / 8 GiB+ | `large` | ≥ 20000 rps | ≥ 20 GB，`total_max_mb: 2048` |

内存按 `-print-budget` 的分解估。用 systemd 部署时再叠一层 `MemoryMax` 做硬天花板。

### 6.5 备份与恢复

控制台"设置 → 备份"可导出配置、规则集、拦截页、IP 名单、例外。
**备份不含任何凭据**（`password_hash` / `api_token` / TOTP 密钥一律不导出）——
备份文件经常被随手放在共享目录里，这是刻意的。

建议把 `config.yaml` 与 `rules/` 一起纳入版本管理（都是纯文本），凭据单独保管。

## 7. 故障排查

### 全站 403

先看响应头 `X-Donothack-Reject`：

| 取值 | 含义 | 怎么办 |
| --- | --- | --- |
| `host` | Host 头不在 `upstream.allowed_hosts` 里 | 验收/联调时最常见，把测试域名加进去 |
| `ratelimit` / `ban` | 被限速或封禁 | 检查 `real_ip` 是否配错（可能把所有人当成同一个来源） |
| `ip_deny` | IP 名单里被拒 | 看控制台 IP 名单 |
| `degrade` | 过载降级到会拒绝的档位 | 看 `/readyz`，按 6.2 处理 |
| （无此头） | 是规则拦的 | 去控制台事件详情看是哪条规则；误报就停用该规则并把样本加进负样本 |

### 全站 502

上游连不上。检查 `upstream.url`、上游是否存活、本机到上游的网络。
`X-Donothack-Reject` 不会有值（502 来自代理层）。

### 一直 429

`real_ip` 没配或配错：前面有 nginx/CDN 时所有请求来源 IP 都是代理地址，
于是共用一个限速桶。修复：把代理网段写进 `real_ip.trusted_proxies`。

### 内存持续上涨 / 被 OOM 杀

看 `/readyz` 的 `degrade.level` 是否在往上走；检查 `limits.max_inspect_body`
与 `max_conns` 是否配得过大（低配机上这两个是内存大户）；用 `-print-budget` 核对档位
是否探测错了（容器/Windows 上很常见）；systemd 加 `MemoryMax` 兜底。

### 控制台进不去

按层排查，每层是独立的：

1. **登录口令**：用 `donothack hash-password` 生成新哈希写进 `admin.password_hash` 重启。
   这是刻意的设计：不提供绕过登录的后门。把那一行删掉重启会重新生成并打印一次。
2. **TOTP 丢失**：调 `POST /api/v1/totp/disable`（带 `username` + `password`、
   `X-Donothack-Console: 1` 头与同源 Origin），或把 `admin.totp_enabled` 改成 `false` 重启。
3. **IP 白名单**：`admin.allow_ips` 配了但不含你现在的 IP —— 回 403，且响应不带产品特征。
4. **登录封禁**：连续输错 `admin.max_login_fails` 次（默认 5）被临时封 15 分钟，
   操作审计里能看到对应的失败记录。
5. **启动就报错说 `admin.gate`**：那是早期版本的第一层 Basic 门槛，已移除 ——
   把 `admin` 段落里的整个 `gate:` 块删掉再启动。


### 规则改了没生效

先看 `GET /config/diff`。规则热重载只对 `rules.dir` / `rules.files` 生效，
且**自测不过会整批拒绝**（控制台会回显具体哪条规则的自测失败）。
引擎模式与阈值可以热改；监听地址、上游、TLS、`real_ip` 必须重启。

### 日志里出现 `category_overflow`

类目分数槽位溢出（内部上限 16 类）。出厂类目只有 9 个，正常不会出现 ——
如果你自定义规则写了很多新类目就会看到。它意味着那些类目的分数只计入总分、
在 `mixed` 模式下不会触发类目阈值。

## 8. 规则

### 8.1 出厂规则

60 条 / 9 个文件，按类目：`sqli` 11、`rce` 12、`xss` 8、`protocol` 7、`lfi` 6、
`scanner` 6、`webshell` 5、`rfi` 3、`upload` 2。变换链去重后 17 条，
其中 37 条可预筛、23 条必须每请求评估。

```bash
donothack rules check -d ./rules   # 校验：正负样本自测不过会整批拒绝加载
donothack rules test -d ./rules   # 只跑规则自带的正负样本
```

**自测走的是完整匹配路径（含预筛），所以"规则其实永远不会被评估"这类问题也会在加载期暴露** ——
这是"手滑写个宽泛正则把线上打挂"的最后一道防线，别关 `rules.self_test`。

### 8.2 怎么写一条规则

```yaml
version: 1
meta:
 name: "我的规则"
 author: "me"
rules:
 - id: MY-1001
  phase: 2           # 1 = 请求头/URL，2 = 请求体
  severity: high        # info | low | medium | high | critical
  category: sqli        # 必须是出厂类目之一（写别的会在加载期被拒）
  score: 5           # 达到入站阈值（默认 5）才拦
  message: "说明这条规则在找什么"
  tags: [sqli]
  targets:
   - collection: ARGS     # 集合名见 8.3
  transforms:         # 见 8.4，按顺序执行
   - urlDecode
   - lowercase
  operator:          # 见 8.5
   name: pm
   params:
    patterns: ["union select"]
  test:            # **必须有**，加载期会跑
   positive: ["1 union select 2"]
   negative: ["union square station", "Please order 3 boxes of paper"]
```

### 8.3 变量集合（targets）

`ARGS`（默认目标，四类参数的合并视图）、`ARGS_NAMES`、`ARGS_COUNT`、
`ARGS_GET`、`ARGS_POST`、`ARGS_JSON`、`ARGS_XML`、`REQUEST_URI`、`REQUEST_URI_LENGTH`、
`REQUEST_PATH`、`REQUEST_METHOD`、`REQUEST_PROTOCOL`、`REQUEST_HEADERS`、
`REQUEST_HEADERS_NAMES`、`REQUEST_COOKIES`、`REQUEST_COOKIES_NAMES`、`REQUEST_BODY`、
`REQUEST_BODY_LENGTH`、`FILES`、`FILES_NAMES`、`FILES_SIZES`、`FILES_MAGIC`。

- `*_NAMES` 匹配的是**参数名**，不是参数值。
- `*_LENGTH` / `ARGS_COUNT` 的值是**数字**（配 `gt` / `lt` 这类数值算子）。
- **响应侧集合（`RESPONSE_*`）在加载期直接报错** —— 本项目不做响应检测。
- `status` 字段除外，`targets` 还支持 `selector` 只匹配某个键，例如
 `{collection: REQUEST_HEADERS, selector: "user-agent"}`。

### 8.4 变换（28 个）

`base64Decode`、`base64DecodeExt`、`cmdLine`、`compressWhitespace`、`cssDecode`、
`doubleUrlDecode`、`escapeSeqDecode`、`hexDecode`、`hexEncode`、`htmlEntityDecode`、
`jsDecode`、`length`、`lowercase`、`md5`、`none`、`normalizePath`、`normalizePathWin`、
`removeComments`、`removeNulls`、`removeWhitespace`、`replaceComments`、`sha1`、
`sqlHexDecode`、`trim`、`uppercase`、`urlDecode`、`urlDecodeUni`、`utf8ToUnicode`。

### 8.5 算子（26 个）

字符串：`contains`、`containsAny`、`startsWith`、`endsWith`、`eq`、`eqIgnoreCase`、
`equals`、`regex`、`regexCaseInsensitive`、`pm`、`pmFromFile`、`unconditionalMatch`。
数值：`gt`、`ge`、`lt`、`le`、`within`、`length`、`entropy`、`validateByteRange`、`luhn`。
语义：`detectSQLi`、`detectXSS`、`detectPathTraversal`、`containsShellChars`、
`isWebshellContent`。
网络：`ipMatch`、`ipMatchFromFile`。
逻辑：`allOf`、`anyOf`、`not`。

规则里写错算子名、参数名或指纹名**都会在加载期报错**，不会静默失效。

### 8.6 写规则的几条硬约束

1. **必须有负样本，而且至少两条**（其中一条要像真实业务流量）。没有负样本的规则会被拒。
2. **优先用 `pm` 而不是 `regex`。** 含交替 `|` 或可选组 `(...)?`/`(...)*`/`{0,n}` 的正则
  **不能进预筛**（会退化成每请求评估，白花 CPU）。
3. **不要只查 `ARGS_GET`** —— 攻击者换成 POST 就绕过了，用默认的 `ARGS`。
4. **弱信号不要给到阈值分。** 弱信号（UA 指纹、值里只有一个引号、裸算术表达式）
  给 1–2 分只记分，靠与其他信号叠加触发拦截；给 5 分就是"自己把站封了"。
  同一个算子里的强弱指纹要拆到不同规则（`detectSQLi` 支持
  `fingerprints` / `exclude_fingerprints` 做这件事）。
5. **不要在预筛字面量上想当然。** 预筛语义是"字面量没命中就跳过这条规则"，
  所以字面量提取错了 = 规则永远不会被评估。`rules check` 的自测会挡住这种情况。

### 8.7 同步规则集

规则集不随二进制 embed、而是随包分发，所以修一条规则本来要重下整个包。手动同步解决了这件事：

```bash
# 取回 → 校验 → 替换本机规则目录（只改磁盘，生效方式见输出）
donothack rules sync -d ./rules            # 取最新发布 tag
donothack rules sync -ref v1.1.0           # 指定版本
donothack rules sync -source http://内网镜像/rules   # 内网镜像
```

控制台的规则页有一个「同步规则」按钮，走同一个逻辑（`POST /api/v1/rules/sync`）。

三条规矩：

- **先自测通过才替换**：新规则先在临时目录里过一遍完整校验（含每条规则的正负样本自测），
  不通过就保持原状并把错误报出来 —— 不会出现"零规则在跑、界面还看着正常"。
- **默认跟最新发布 tag**，而不是默认分支：默认分支上随时可能是半成品提交。
- **指纹相同就跳过**，不做无意义的替换与重载。

同步完记得让进程重新加载规则（`POST /api/v1/rulesets/reload`，或重启）。


## 9. 架构与目录

数据面与控制面严格分离：**数据面只读不可变快照、永不阻塞在控制台**；
所有写操作走 `control.Apply`（解析 → 校验 → 内置语料自测 → 原子替换 → 失败回滚）。
控制台独立端口、独立 mux、独立限流，**控制台流量不进检测引擎**（免得规则把管理员操作拦掉）。

```
cmd/donothack/    主程序与 CLI
cmd/plainproxy/    性能基线用的裸反向代理（不给生产用）
cmd/loadgen/     压测客户端
internal/parser/   请求解析与规范化（防绕过的核心）
internal/rules/    规则加载、索引、预筛、求值
internal/operator/  算子（pm / regex / detectSQLi / detectXSS / entropy …）
internal/transform/  28 个变换（dst 化，热路径不分配）
internal/engine/   检测引擎与决策
internal/pipeline/  数据面主流程（限速 → 检测 → 决策 → 转发）
internal/control/   控制面：唯一写入口
internal/console/   控制台后端
web/         控制台前端（原生 ES module，无构建链，go:embed）
rules/        出厂规则集（9 个文件 / 60 条）
scripts/       验证与压测脚本（Python）
```

CLI：

```
donothack -c config.yaml       启动数据面
donothack rules check -d ./rules   校验规则集
donothack rules test -d ./rules   跑规则自带的正负样本
donothack test -r req.http      离线跑一条原始请求（看命中链路）
donothack hash-password        生成控制台口令哈希
donothack version           打印版本与许可
```

启动参数：`-version`、`-check-config`（只校验配置后退出，适合部署脚本与 CI）、
`-print-budget`、`-no-rules`（不加载规则只做纯转发，调试用）。

## 10. 许可

本项目采用 **[donothack 许可 v1.0](LICENSE)：自用免费，禁止转售。**

| 用途 | 可以吗 |
| --- | --- |
| 个人学习、研究、试验、业余项目 | 可以，免费 |
| 部署在自己的生产环境、用于自己的业务（含公司内部系统，不论是否营利） | 可以，免费 |
| 修改、二次开发，用于内部系统或自有产品 | 可以，免费 |
| 免费复制、分发给别人（附上许可文本） | 可以，免费 |
| 销售、转售、出租本软件或其修改版本 | 需要授权 |
| 作为付费产品/付费服务的一部分对外提供 | 需要授权 |
| 基于它提供有偿的托管、代管、SaaS 或安全服务 | 需要授权 |
| 移除版权声明或许可文本 | 不可以 |

**版权所有者（guaidao2 & coolmoon）本人及其所属实体不受限制**，
可自由使用、修改与商用 —— 许可约束的是被许可方，不约束版权人自己。

一句话：自己用、自己改、免费给别人用都行；拿它赚钱先来谈授权。
条款以 [LICENSE](LICENSE) 为准。

WAF 是安全产品：正式压上生产流量之前，请先在你自己环境里过一遍误报与漏报。

> 说明：这是一份为"自用免费、禁止转售"这个意图写的短许可，不是 OSI 认可的开源许可
> （禁止转售与开源定义冲突），因此它是**源码可见**而非开源。如果你想用更通行的标准文本，
> 可以换成 BSL-1.1（条款里带"额外使用授权"槽位，通常附"若干年后自动转 Apache-2.0"）
> 或 Elastic License 2.0（禁止作为托管服务提供，但不禁转售拷贝）。

## 11. 附录

- [版本历史](CHANGELOG.md)
- 测试语料的分类口径见 [testdata/corpus/README.md](testdata/corpus/README.md)

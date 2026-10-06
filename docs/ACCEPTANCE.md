# P6 验收报告：crackweb 打靶场

> 本文是**实测记录**，不是承诺。所有数字都是本机跑出来的，命令与参数完整可复现。
> 性能数字只作参考（真机基线待补，见 docs/PERFORMANCE.md）。

## 1. 验收口径

| 项 | 值 |
| --- | --- |
| 扫描器 | crackweb 1.6.4（作者自建；`.tmp/crackweb/crackweb_1.6.4_windows_amd64/crackweb.exe`） |
| 靶场 | http://127.0.0.1:8787（作者自建漏洞靶场） |
| 被测 | donothack，监听 127.0.0.1:18080，`engine.mode: block` |
| 判据 | **主动注入类 findings 归零**（或拦到扫描器无法确认）；误报可控 |

扫描命令（两轮完全一致，保证可比）：

```bash
crackweb --lang zh crawl -u <目标> --depth 2 --max-pages 25 --rate 40 --no-color -o <报告>
```

## 2. 结果总览

| 指标 | 直连靶场（基线） | 经 donothack（首轮，58 条规则） |
| --- | --- | --- |
| findings 总数 | 14 | 14 |
| 其中**注入类**（tags 含 `injection`） | **4**（反射型 XSS ×1、SSTI ×3） | **3**（SSTI ×3） |
| 请求数 | 32386 | 31904 |
| 耗时 | 13m33.6s | 13m21.2s |
| 爬取 | 30 页 / 553 URL | 30 页 / 553 URL |

**经 WAF 后，反射型 XSS 消失**（基线有、经 WAF 没有）—— 说明 XSS 类 payload 被拦在了门外。

首轮扫描时规则集里**没有 SSTI 规则**（59 条里缺这一类），SSTI 因此仍是 3 条。
这正是"必须真跑一遍扫描器"的价值：单元测试与语料都发现不了"整整一类攻击没规则"。

## 3. 补上 SSTI 后的定点复测

新增规则 `SSTI-3001`（`rules/70-ssti.yaml`）后，用 `crackweb scan` 对两个端点定点复测：

| 端点 | 复测结果 |
| --- | --- |
| `/bruteplayground/by-order-id?orderId=3321`（原反射型 XSS） | **0 条注入类 finding** |
| `/expr/injection?a=1`（原 SSTI） | 1 条 `ssti`（见 §4.1，形态不同） |

手工验证 `SSTI-3001` 的实际拦截（`{{...}}` 模板语法的各种编码变体）：

| 变体 | 结果 |
| --- | --- |
| `{{1999*1999}}` 原始 | 403 已拦 |
| `%7B%7B1999*1999%7D%7D` URL 编码 | 403 已拦 |
| 双写 URL 编码 | 403 已拦 |
| `&#123;&#123;1999*1999&#125;&#125;` HTML 实体 | 403 已拦 |
| `&#x7b;...` 十六进制实体 | 403 已拦 |
| JSON 内层字段（值级展开） | 403 已拦 |
| `Hello {{name}} welcome` 正常模板文案 | 200 放行（**不误伤**） |

## 4. 残余 finding 与原因（**如实列出**）

### 4.1 SSTI：`a=1999*1999`（**裸算术表达式**）

crackweb 的 SSTI 检测会发**不带模板语法**的 `1999*1999`，依据是靶场把表达式算了出来
（响应里出现 `3996001`）。它测的是"应用把用户输入当代码求值"，不是模板注入语法本身。

**为什么不拦**：裸算术在正常业务里并不罕见 —— `?resolution=1920*1080`、
`?size=100*100`、计算器类应用的 `?expr=1+1`。把这些拦掉换来的误报远大于收益。
真正能治本的是**响应侧**检测（响应里出现求值结果），而本项目**按设计只做请求侧**
（docs/DESIGN.md §1）—— 这条边界是有意划的。

**已做的折中**：新增 `PROBE-2001`（`rules/75-probe.yaml`，score 2）识别
"参数值整个就是算术表达式"的形态。**只记分不拦截**，但会进事件与类目统计 ——
运维在控制台里能看到"有人在拿表达式探这个接口"，进而给那个路径单独加严
（控制台的规则管理与例外就是干这个的）。

### 4.2 `exposed-path`：`/swagger/v1/swagger.json`

靶场对外提供了自己的 API 描述文件。这属于**应用自身的暴露**，不是注入：
- 拦 `/swagger/` 会打死正当的 API 文档站点；
- 攻击者真正要的是文件内容，而它本来就是要给外部看的（或本该限内网）。

**建议**：在应用侧收口（鉴权或下线），而不是在 WAF 里按路径拦。

### 4.3 `host-header`：应用回显 Host

实测：直连靶场时，应用会把伪造的 `Host`（以及 `X-Forwarded-Host`）回显进响应。
这是**应用的问题**（可导致密码重置投毒、缓存投毒）。

**这次为它补了一个真能力**：`upstream.allowed_hosts` 白名单（支持 `*.example.com`）。
配置后实测：

| Host | 结果 |
| --- | --- |
| `127.0.0.1` / `127.0.0.1:18080` / `localhost` | 200 正常 |
| `evil-marker.example` | **400 拒绝，且不回显 Host** |
| `127.0.0.1.evil.example` | **400 拒绝** |

默认留空（不校验），只在站点域名固定时开启。

### 4.4 `passive-*`（缓存头、Cookie 属性、安全响应头、明文传输、SRI）

这些是**应用与传输层**的问题，不归 WAF 管：
- `passive-cache-control`：敏感响应缺 `Cache-Control`；
- `passive-cookie-flags`：Cookie 缺 `Secure`/`HttpOnly`/`SameSite`；
- `passive-security-headers`：缺 HSTS/CSP/X-Frame-Options 等；
- `passive-insecure-transport`：登录页走明文 HTTP；
- `passive-sri`：外链脚本缺完整性校验。

WAF 能做的有限部分（给响应补安全头）属于**响应侧改写**，本项目不做（不缓冲、不改写响应）。

## 5. 误报可控性（这是 WAF 能否上线的真正门槛）

| 验收项 | 结果 |
| --- | --- |
| 攻击语料 `testdata/corpus/positive`（23 条） | **23/23 被拦** |
| 正常业务语料 `testdata/corpus/negative`（17 条） | **17/17 放行（零误报）** |
| 单一弱信号语料 `detect/` | 1/1 符合设计（记分不拦） |
| 透传保真度 `scripts/passthrough.py` | **6/6 完全一致**（状态码/长度/体哈希/Content-Type/响应头） |
| 规则集自测（59 条规则的正负样本） | 全过（不过则整批拒绝加载） |

## 6. 复现步骤

```bash
# 1) 起 WAF（block 模式）
dist/donothack.exe -c .tmp/p4/config.yaml

# 2) 基线：直连靶场
.tmp/crackweb/crackweb_1.6.4_windows_amd64/crackweb.exe --lang zh crawl \
  -u http://127.0.0.1:8787 --depth 2 --max-pages 25 --rate 40 -o .tmp/p6/baseline-direct.json

# 3) 对照：经 WAF
.tmp/crackweb/crackweb_1.6.4_windows_amd64/crackweb.exe --lang zh crawl \
  -u http://127.0.0.1:18080 --depth 2 --max-pages 25 --rate 40 -o .tmp/p6/waf-block.json

# 4) 定点复测（快，约 2 秒）
.tmp/crackweb/crackweb_1.6.4_windows_amd64/crackweb.exe --lang zh scan \
  -u "http://127.0.0.1:18080/expr/injection?a=1" --quiet -o .tmp/p6/targeted-ssti.json

# 5) 语料与透传回归
python scripts/acceptance.py --waf 127.0.0.1:18080 --corpus testdata/corpus
python scripts/passthrough.py --direct http://127.0.0.1:8787 --waf http://127.0.0.1:18080
```

## 7. 结论

- **反射型 XSS：归零**（基线有 → 经 WAF 无）。
- **SSTI（模板语法形态）：已拦**，六种编码变体实测全部 403，正常模板文案不误伤。
- **注入类残余 1 条**：裸算术表达式求值（`a=1999*1999`）。它不含任何注入语法，
  请求侧无法在不误伤正常算术参数的前提下拦截；已用 `PROBE-2001` 做到"可见不误伤"，
  并如实记录为能力边界。**这一条不能算"已解决"，只能算"已解释 + 已可见"**。
- 非注入类残余（swagger 暴露、Host 回显、被动配置项）分别给了定位与处置建议；
  其中 Host 回显已提供 `upstream.allowed_hosts` 主动收口。
- 误报侧：攻击语料 23/23、业务语料 17/17、透传 6/6。

---

## 第二轮完整验收（59 条规则集，tag `v1.0.0-rc1`）

### 条件

| 项 | 值 |
| --- | --- |
| 扫描器 | crackweb 1.6.4（`--depth 2 --max-pages 25 --rate 40`） |
| 目标 | 经过 donothack（`.tmp/p4/config.yaml`，59 条规则 / 16 条链） |
| 请求数 | 32986（基线 32386，差 1.9%，可比） |
| 端点 | 40（与基线一致） |
| 耗时 | 13m52s |

### 结果对比

| | 直连基线（无 WAF） | 首轮（54 条规则） | **本轮（59 条规则）** |
| --- | --- | --- | --- |
| 全部 findings | 14 | 14 | **13** |
| **主动注入类** | **4** | **3** | **3** |
| ├ 反射型 XSS | 1 | 0 | **0** |
| ├ SSTI（模板语法 `{{1999*1999}}`） | 3 | 0 | **0** |
| └ SSTI（裸算术 `1999*1999`） | 0 | 3 | 3 |
| host-header | 0 | 1 | **0** |
| 非注入类（`passive-*` / `exposed-path`） | 9 | 10 | 10 |

**可拦的注入类全部归零**：反射型 XSS 归零、SSTI 的**模板语法形态**归零。
`host-header` 也归零（靠 `upstream.allowed_hosts` 主动收口）。

### 残余：3 条裸算术 SSTI（已接受，附量化理由）

crackweb 的 payload 是**推导**出来的：基代 `{{1999*1999}}` 被拦后，它去掉了花括号，
退化成裸算术 `1999*1999`交给靶场 —— 而靶场的 `/expr/injection` **把任何值都当表达式求值**
（返回 3996001），所以它仍然"成功"。

**为什么不为它写拦截规则**：请求侧看到的只是一个普通参数值，
`?resolution=1920*1080`、`?size=100*100`、`?dim=10*20` 与之**在语法上完全同类**。
拦它 = 给所有"宽×高"类参数制造误报，而这类参数在电商、图床、打印类站点上很常见。
`a=1999*1999` 与 `resolution=1920*1080` 在请求侧不可区分 —— 这不是规则写得不够好，
是**信息不足**：判据在响应里（值是否被求值），而本项目按设计只做请求侧（DESIGN.md §1）。

现有处置：`PROBE-2001`（score 2，只记分不拦），事件在控制台可见、可告警。
治本要么应用侧收口（不要把用户输入当表达式），要么上响应侧检测（超出本项目范围）。

### 误报侧证据

| 验证 | 结果 |
| --- | --- |
| 语料验收 `scripts/acceptance.py` | **positive 23/23 拦截、negative 17/17 放行**、detect 1/1 只记分 |
| 透传保真度 `scripts/passthrough.py` | **6/6 完全一致**（状态码/长度/体哈希/Content-Type/响应头） |
| 性能（见 PERFORMANCE.md 附录 P6） | 35332 rps，比裸代理基线（27429）**快 28.8%**，RSS 44.2 MiB |

### 本轮另外发现的两个"脚本级"缺陷（都已修）

1. **语料验收一度全红（400 而非 403）**：测试配置的 `upstream.allowed_hosts` 只放行了
   `127.0.0.1/localhost`，而语料用的是 `*.example.com` —— 请求在 **Host 白名单层**
   就被拒了，根本没走到规则。加上 `*.example.com` 后全绿。
   教训：拒绝的**来源层**要能看出来，否则会把"另一层生效了"误判成"规则失效"。
2. **透传脚本把每条都判成不一致**：`--waf 127.0.0.1:18080` 少写 `http://`，
   urllib 抛 `unknown url type` —— 满屏红色差异看起来像 WAF 篡改了响应。
   现在缺 scheme 自动补全。

### 仍未达成 / 仍缺的

* **主动注入类归零**这一条：3 条裸算术 SSTI 属"请求侧不可判定"，是**已接受的残余**，
  不是漏拦。若要严格归零，只能上响应侧检测（与本项目设计范围冲突）。
* **真机 2C2G 基线**：需要一台目标档 VPS 才能测，本机数字不作承诺。
* `BenchmarkEngine_NoMatch` 的 0 allocs/op 门禁（实测 21，方案见 PERFORMANCE.md 附录 P6）。

---

## 第三轮：编码载荷绕过（**已修**，tag `v1.0.0-rc2`）

### 发现

crackweb 1.6.4 用**定向扫描**打 `?id=<base64(JSON)>` 形态的接口时，拿到了 4 条 finding，
其中两条是**注入类**：

```
[Critical] SQL injection (error-based)        query:id.id   Payload: '
[High]     SQL injection (boolean-based blind) query:id.id   Payload: 1 AND 1=2
```

关键点：**同样的 payload 明文放在普通参数里是拦得住的**（403），
编码进 base64(JSON) 之后完全绕过（200）。这正是"载荷不一定是明文的"。

### 根因（两层，缺一不可）

1. **展开结果没进规则实际匹配的集合。**
   `ParseRequest` 末尾用 `MergeInto` 构造 `ARGS` 合并视图，而 59 条规则**全部**对着 `ARGS` 匹配；
   `ExpandNestedDocs`（值级文档展开）却是在这之后执行、且只写 `ArgsJSON` ——
   展开进了一个**规则看不到的副本**，等价于完全没展开。
   原来的单测只断言"`ArgsJSON` 里有 payload"，恰好绕过了这个问题。
2. **指纹覆盖缺口。** `detectSQLi` 只认**恒真**比较（`1=1`、`2>1`），
   而布尔盲注用的是**矛盾式**（`1 AND 1=2`）—— 只认恒真就是漏检；
   单独的引号 `'`（错误型注入的经典探测）则完全没有任何指纹。

### 修复

| 层 | 改动 |
| --- | --- |
| parser | `ExpandNestedDocs` 同时写 `Args`（规则实际匹配的合并视图）与 `ArgsJSON` |
| operator | 新增 `boolean comparison` 指纹：`and/or` + 操作数 + 比较符 + 操作数，**不区分真假** |
| operator | 新增 `quote probing` 指纹：整值就是引号、或数字后紧跟引号（`1'`） |
| 测试 | `internal/engine/nested_doc_test.go`：**从"引擎裁决"这一端**写 6 条回归（4 正 2 反） |
| 语料 | 新增 positive 5 条、negative 2 条（含 `O'Brien`、`it's a nice day` 反面对照） |

### 验证

| 项 | 结果 |
| --- | --- |
| 定向重扫（同一 URL，2603 请求 / 7.4s） | 4 条 → **1 条**，**注入类 0**（只剩 `exposed-path` swagger，应用侧） |
| 语料验收 | 47 例：**positive 28/28 拦、negative 18/18 放**、detect 1/1 |
| 规则集自测 | 全部正负样本通过 |
| 透传保真度 | 6/6 一致 |
| 逐 payload 离线核对 | 10 例全对（含 `O'Brien`、`it's a nice day` 不误报） |

### 教训（写进了 docs/DESIGN.md §8.7）

* **载荷不一定是明文的** —— 值可能是 JSON、base64(JSON)、多层编码，展开是必需的，不是可选的。
* **展开之后的字段必须落到规则真正匹配的集合里** —— "产出了字段"和"规则能看到"是两件事。
* **测试要从结论这一端写**：断言"引擎拦住了"而不是"函数产出了字段"。
  前者能挡住这次这个 bug，后者挡不住。

### 第三轮补充：**完整爬取没有覆盖到编码绕过，定向扫描才覆盖到**

这一点比数字本身重要，写下来避免下次又只看一个数：

| 扫描方式 | 请求数 | findings | 主动注入类 | 是否打到 `base64(JSON)` 绕过 |
| --- | --- | --- | --- | --- |
| 完整爬取（`crawl --depth 2`） | 31910 | 13 | 3（裸算术 SSTI） | **没有** |
| 定向扫描（`scan -u .../id-b64-json?id=...`） | 2603 | **4 → 1** | **4 → 0** | **有** |

原因：`crawl` 模式对**发现到的参数**用固定 payload 集；
而 `scan -u` 模式会对给定 URL 的参数做**结构推导 + 编码代数升级**
（把值当 JSON 解析、逐字段注入、再套 base64）。编码型绕过只有后者能打出来。

⇒ **验收流程同时跑两种模式**，只看爬取的数字会漏掉整整一类绕过。

复现命令（两行，可重跑）：

```bash
# 1) 完整爬取
.tmp/crackweb/crackweb_1.6.4_windows_amd64/crackweb.exe crawl \
  -u http://127.0.0.1:18080 --depth 2 --max-pages 25 --rate 40 -o .tmp/p6/crawl.json

# 2) 定向扫描（编码参数文档这条线）
.tmp/crackweb/crackweb_1.6.4_windows_amd64/crackweb.exe scan \
  -u "http://127.0.0.1:18080/user/id-b64-json?id=eyJ1aWQiOjEsIm1sIjoiMSJ9" \
  -o .tmp/p6/targeted-b64json.json
```

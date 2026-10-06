# 规则 DSL 规格

> 状态：待评审（v0 设计稿）
> 配套：`docs/DESIGN.md`
> 实现阶段：P2

---

## 1. 设计原则

1. **安全工程师能独立写规则**，不需要写 Go、不需要重新编译。
2. **默认安全**：规则的默认目标集合是"全部用户输入"，写漏了也不会漏检（宁可多查不可少查）。
3. **可读优先于紧凑**。禁止为了少写几个字发明隐晦语法。
4. **编译期报错，运行期不猜**。未知的 transform / operator 名字直接拒绝加载整批规则。
5. **每条规则必须可追溯**：ID、类目、严重度、来源文件行号、正负样本。

---

## 2. 文件组织

```
rules/
  00-protocol.yaml     协议违规（畸形请求、请求走私迹象、超长字段）
  10-scanner.yaml      扫描器与工具指纹（sqlmap、nikto、nuclei、awvs…）
  20-sqli.yaml         SQL 注入
  30-xss.yaml          跨站脚本
  40-rce.yaml          命令注入 / 代码执行
  50-lfi.yaml          路径穿越 / 文件包含
  60-webshell.yaml     Webshell 上传与访问
  70-leakage.yaml      响应侧敏感数据泄露 —— **本轮不提供**（不做响应侧检测，见 docs/DESIGN.md §12）
  90-exceptions.yaml   白名单与例外
```

文件名数字前缀决定加载顺序；同阶段内按严重度降序执行。

---

## 3. 规则结构

```yaml
version: 1
meta:
  name: "SQL 注入检测"
  author: "qingli"
  category: sqli

rules:
  - id: SQLI-942100
    enabled: true
    phase: 2
    severity: critical
    category: sqli
    score: 5
    message: "SQL 注入特征：UNION SELECT 注入"
    tags: [sqli, owasp-a03, union-select]

    targets:
      - collection: ARGS
      - collection: REQUEST_HEADERS
        selector: "cookie"
      - collection: REQUEST_URI

    transforms:
      - removeComments
      - urlDecode
      - compressWhitespace
      - lowercase

    operator:
      name: detectSQLi
      params:
        min_fingerprint_len: 8

    action:
      type: block
      status: 403

    test:
      positive:
        - "1' UNION SELECT 1,2,3--"
        - "admin'/**/UNION/**/SELECT/**/password/**/FROM/**/users"
      negative:
        - "select your country"
        - "union square station"
```

---

## 4. 字段说明

### 4.1 顶层字段

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `version` | int | 是 | DSL 版本，当前为 `1`。版本不符拒绝加载。 |
| `meta.name` | string | 是 | 规则集名称，进审计与指标。 |
| `meta.author` | string | 否 | 作者。 |
| `meta.category` | string | 否 | 整个文件的默认类目，规则可覆盖。 |
| `rules` | list | 是 | 规则列表。 |
| `exceptions` | list | 否 | 例外（见 §8）。 |

### 4.2 规则字段

| 字段 | 类型 | 必填 | 默认 | 说明 |
| --- | --- | --- | --- | --- |
| `id` | string | 是 | — | 全局唯一。命名规范见 §9.1。 |
| `enabled` | bool | 否 | `true` | 关闭后进规则集但不执行，仍可在自测中看到。 |
| `phase` | int | 是 | — | **本轮只支持 1 和 2**（请求头 / 请求体与参数）。3/4 为响应侧，保留但未实现；5 为收尾阶段，不可写规则。 |
| `severity` | enum | 是 | — | `critical` / `high` / `medium` / `low` / `info`。 |
| `category` | string | 是 | 继承 `meta` | 决定加多少分（见 `scoring.categories`）。 |
| `score` | int | 否 | 取类目默认分 | 本条规则的加分数，可覆盖类目默认。 |
| `message` | string | 是 | — | 人类可读说明，进审计。禁止写会被回显给用户的内容。 |
| `tags` | list | 否 | `[]` | 分类标签，用于筛选、统计、批量开关。 |
| `targets` | list | 是 | — | 作用对象，见 §5。 |
| `transforms` | list | 否 | `[]` | 变换链，见 §6。顺序即执行顺序。 |
| `operator` | object | 是 | — | 匹配算子，见 §7。 |
| `action` | object | 否 | 继承模式默认 | 命中动作覆盖，见 §4.3。 |
| `hard_block` | bool | 否 | `false` | true = 命中即终止本阶段剩余规则并立即拦截，不看分数。 |
| `chain` | bool | 否 | `false` | 链式规则：本条命中才评估下一条（用于"参数里同时出现 A 和 B"）。 |
| `test` | object | 否 | — | 内置正负样本，参与自测与 `donothack rules test`。**新规则必填。** |

### 4.3 `action`

```yaml
action:
  type: block          # block | log | tarpit | challenge | drop | redirect
  status: 403          # block 时的 HTTP 状态码，默认 403
  redirect_url: ""     # type=redirect 时的目标
  tarpit_delay: 5s     # type=tarpit 时的延迟
  ban_ip: true         # 命中后是否临时封禁来源 IP
  ban_duration: 300s
```

不写 `action` 时按 `engine.mode` 与评分解算：

- `detect` 模式：任何命中都只 `log`。
- `block` 模式：达到入站阈值才 `block`。
- `mixed` 模式：看类目阈值。

---

## 5. 变量集合（targets）

### 5.1 集合清单

**请求侧**

| 集合 | 内容 |
| --- | --- |
| `ARGS` | 全部参数合并（GET + POST + JSON + XML）。**规则默认应使用这个。** |
| `ARGS_GET` | query string 参数 |
| `ARGS_POST` | form-urlencoded / multipart 普通字段 |
| `ARGS_JSON` | JSON body 展开后的叶子值，键为点号路径 |
| `ARGS_XML` | XML 文本节点与属性值 |
| `ARGS_NAMES` | 参数名（不是值）——用于检测参数名里的注入 |
| `REQUEST_URI` | 原始 URI（含 query） |
| `REQUEST_PATH` | 规范化后的路径 |
| `REQUEST_METHOD` | 方法 |
| `REQUEST_PROTOCOL` | 协议版本 |
| `REQUEST_HEADERS` | 全部请求头 |
| `REQUEST_HEADERS_NAMES` | 请求头名 |
| `REQUEST_COOKIES` | Cookie 值 |
| `REQUEST_COOKIES_NAMES` | Cookie 名 |
| `REQUEST_BODY` | 请求体原文（针对整体 payload 的规则） |
| `FILES` | multipart 文件名 |
| `FILES_NAMES` | multipart 字段名 |
| `FILES_SIZES` | 文件大小 |
| `FILES_MAGIC` | 文件头 16 字节（hex） |
| `REMOTE_ADDR` | 真实客户端 IP |
| `TX` | 事务级临时变量（供链式规则传递） |

**响应侧**（**本轮未实现**，见 `docs/DESIGN.md` §12）

donothack 本轮只做请求侧检测，以下集合在解析层不会装填。名称保留是为了将来若恢复响应检测时规则无需改写；**写针对这些集合的规则在加载期会被拒绝并给出明确报错**（不允许写一条永远不生效的规则）。

| 集合 | 内容 | 状态 |
| --- | --- | --- |
| `RESPONSE_STATUS` | 状态码 | 未实现 |
| `RESPONSE_HEADERS` | 响应头 | 未实现 |
| `RESPONSE_BODY` | 响应体 | 未实现 |
| `RESPONSE_CONTENT_TYPE` | Content-Type | 未实现 |

**派生**

| 集合 | 内容 |
| --- | --- |
| `ARGS_COUNT` | 参数个数（用于异常参数数量检测） |
| `REQUEST_URI_LENGTH` | URI 长度 |
| `REQUEST_BODY_LENGTH` | 请求体长度 |

### 5.2 选择器语法

```yaml
targets:
  - collection: ARGS                      # 全部参数
  - collection: ARGS
    selector: username                    # 精确键
  - collection: REQUEST_HEADERS
    selector: "user-agent"                # 头部名小写
  - collection: ARGS
    selector: "/^id_[0-9]+$/"             # 正则键（斜杠包裹）
  - collection: REQUEST_COOKIES
    selector: "!session"                  # 排除某个键
  - collection: ARGS
    count: true                           # 只取个数，不取内容（与 operator: ge 搭配）
```

同一个 target 内多个 selector 是"或"关系；多个 target 之间也是"或"关系（任一命中即算命中）。

### 5.3 空值与缺失的语义

- 集合不存在（如 GET 请求查 `ARGS_POST`）：**不匹配**，不算命中，不算错误。
- 键存在但值为空串：**参与匹配**（空串可能是有意义的，如 `?id=`）。
- 值含 NUL 字节：截断到 NUL 之前参与匹配，同时记一条 `parse_error` 事件。

---

## 6. 变换（transforms）

按数组顺序依次执行，前一个的输出是后一个的输入。

| 名称 | 说明 | 参数 |
| --- | --- | --- |
| `none` | 原样 | — |
| `lowercase` | 转小写 | — |
| `uppercase` | 转大写 | — |
| `urlDecode` | 单次 URL 解码 | — |
| `urlDecodeUni` | 解码 `%uXXXX` 形式 | — |
| `doubleUrlDecode` | 连续解码两次（对抗双写绕过） | — |
| `htmlEntityDecode` | `&#x41;` `&lt;` 等 | — |
| `jsDecode` | `\u0041` `\x41` `\u{41}` | — |
| `base64Decode` | Base64 解码；非法则原样返回 | — |
| `base64DecodeExt` | 容忍 URL-safe 与缺失 padding | — |
| `sqlHexDecode` | `0x41` 或 `X'4142'` | — |
| `cssDecode` | `\41` CSS 转义 | — |
| `removeComments` | 去 `/**/`、`--`、`#`、`<!-- -->` | — |
| `removeNulls` | 去 `\x00` | — |
| `compressWhitespace` | 连续空白折成一个空格 | — |
| `removeWhitespace` | 去所有空白 | — |
| `trim` | 去首尾空白 | — |
| `normalizePath` | 路径规范化（`..`、`//`、`\`） | — |
| `normalizePathWin` | 同上，反斜杠也当分隔符并转换 | — |
| `replaceComments` | 注释替换为单个空格（避免拼接绕过） | — |
| `length` | 把值替换为其长度（字符串形式的数字） | — |
| `hexEncode` / `hexDecode` | 十六进制编解码 | — |
| `sha1` / `md5` | 摘要（配合已知恶意哈希库） | — |
| `cmdLine` | 命令行长参数归并 | — |
| `utf8ToUnicode` | 归一为 `\uXXXX` 形式 | — |
| `escapeSeqDecode` | ANSI C 转义（`\n` `\t` `\\`） | — |

**约束**

- 变换**不得原地修改**输入切片。
- 每个变换有迭代上限（默认 8 次），防止嵌套编码把 CPU 拖死。
- 变换失败（如非法 base64）**返回原值**并记 `transform_error` 计数，不中断规则评估。
- `length` 之类改变语义的变换要写在链尾。

---

## 7. 算子（operators）

### 7.1 字符串类

| 名称 | 参数 | 说明 |
| --- | --- | --- |
| `eq` | `value` | 全等（大小写敏感） |
| `eqIgnoreCase` | `value` | 全等（忽略大小写） |
| `contains` | `value` | 子串包含 |
| `containsAny` | `values: []` | 任一子串 |
| `startsWith` / `endsWith` | `value` | 前后缀 |
| `regex` | `pattern`, `capture: bool` | RE2 正则。**禁止 PCRE 特性**（反向引用、环视），编译期报错。 |
| `pm` | `patterns: []`, `match_all: bool` | 多模式匹配（Aho-Corasick）。规则里的高频关键词一律用 pm，不要写一堆 regex。 |
| `pmFromFile` | `file`, `match_all` | 从文件加载模式（大词表，如敏感路径、恶意 UA） |
| `equals` | `value` | 与 `eq` 同义（兼容 SecRules 习惯） |

### 7.2 数值类

| 名称 | 参数 | 说明 |
| --- | --- | --- |
| `gt` / `ge` / `lt` / `le` | `value` | 数值比较（配合 `count: true` 或 `length` 变换） |
| `within` | `min`, `max` | 区间 |
| `validateByteRange` | `range: "1-255"` | 字节范围外即命中（协议违规） |

### 7.3 语义类

| 名称 | 参数 | 说明 |
| --- | --- | --- |
| `detectSQLi` | `min_fingerprint_len` | SQLi 词法指纹（libinjection 风格）。比正则准确得多。 |
| `detectXSS` | `min_fingerprint_len` | XSS 上下文指纹 |
| `detectPathTraversal` | `depth` | 目录穿越语义检测（含多层编码） |
| `containsShellChars` | `allow: []` | 命令注入特征字符与结构 |
| `isWebshellContent` | — | PHP/JSP/ASP 危险函数组合特征 |
| `entropy` | `min_bits: 4.0`, `min_len: 20` | 香农熵（抓密钥、随机串、混淆载荷） |
| `luhn` | — | 银行卡号校验 |
| `verifyCC` | — | Luhn + 卡 BIN 校验 |
| `isValidJWT` | — | JWT 结构识别（配合泄露检测） |

### 7.4 网络类

| 名称 | 参数 | 说明 |
| --- | --- | --- |
| `ipMatch` | `cidrs: []` | IP/CIDR 匹配 |
| `ipMatchFromFile` | `file` | 从文件加载名单（威胁情报） |
| `rblLookup` | `zone` | DNSBL 查询（**默认关**，有外呼延迟，谨慎） |
| `geoLookup` | `countries: []` | 地理位置（需 MMDB 文件，可选依赖） |

### 7.5 逻辑组合

| 名称 | 参数 | 说明 |
| --- | --- | --- |
| `allOf` | `operators: []` | 全部命中才算命中 |
| `anyOf` | `operators: []` | 任一命中（等价于多条 target） |
| `not` | `operator` | 取反 |
| `unconditionalMatch` | — | 恒真（用于纯"记录"规则） |

`allOf` / `anyOf` 的组合深度上限 4 层，防规则集失控。

---

## 8. 例外与白名单

```yaml
exceptions:
  - id: EXC-0001
    reason: "后台富文本编辑器提交 HTML，必须放行 XSS 规则"
    expires: 2027-01-01
    match:
      paths: ["/admin/editor/save"]
      methods: ["POST"]
      source_ips: ["10.0.0.0/8"]
      headers:
        X-Internal-Token: "/^[a-f0-9]{32}$/"
    disable_rules: ["XSS-*"]        # 通配符匹配 rule id
    disable_categories: []
    mode: skip                       # skip=完全不过规则 | detect_only=只记录不拦

  - id: EXC-0002
    reason: "健康检查高频请求，不计入限速"
    match:
      paths: ["/healthz", "/readyz"]
    skip_ratelimit: true
    disable_rules: ["*"]
```

**硬性要求**

- `reason` 必填，且不得为空或"临时"。
- `expires` 必填，最长不超过 1 年。到期后加载器输出 `level=warn`，并在 `/readyz` 的详情里提示。
- 例外命中也要进审计（`verdict: pass, exception_id: EXC-0001`），否则例外就成了黑洞。
- `disable_rules: ["*"]` 会让该路径完全裸奔，加载器对这条用法额外告警一次。

---

## 9. 编写约定

### 9.1 规则 ID 命名

`<类目>-<编号>`，全大写，编号段位预分配：

| 段 | 用途 |
| --- | --- |
| `PROTO-1xxx` | 协议违规 |
| `SCAN-2xxx` | 扫描器指纹 |
| `SQLI-4xxx` | SQL 注入 |
| `XSS-5xxx` | XSS |
| `RCE-6xxx` | 命令注入 / 代码执行 |
| `LFI-7xxx` | 路径穿越 / 文件包含 |
| `RFI-8xxx` | 远程文件包含 |
| `WS-9xxx` | Webshell |
| `LEAK-3xxx` | 响应侧泄露 |
| `UPLOAD-1xxx` | 上传相关 |

新规则从段位末尾往上加，不复用已删除的编号（否则审计日志里的历史规则 ID 会对不上）。

### 9.2 写规则的硬约束

1. **优先用语义算子，其次 `pm`，最后才 `regex`。** 复杂正则既慢又容易误报。
2. **正则必须锚定或带足够上下文**，禁止 `.*` 开头的宽泛模式。
3. **每条规则必须带 `test.positive` 和 `test.negative`**，负样本至少两条，其中至少一条是真实业务流量形态。
4. **`score` 保守**。宁可分数低一点让多条规则叠加命中，也不要单条高分散布误报。
5. **`message` 不写 payload**，只写定性描述。
6. **参数名相关规则**（`ARGS_NAMES`）单独成组，分数给低（2~3），因为参数名里出现 `select` 也可能是正常业务命名（如 `select_all`）。
7. **改动已有规则必须连带改它的负样本**，并在 `CHANGELOG.md` 记一笔原因。
8. **不写针对特定 IP 的规则**，那属于例外，不属于规则。
9. **字面量长度 ≥ 3 字节**。短于 3 字节的字面量（如 `1`、`a`、`..`）不进预筛自动机 —— 它们会让自动机在每个输入上都命中，预筛等于失效。这类规则会被标记为"无预筛"直接执行，编译期统计数量并在超过规则集 20% 时告警。
10. **禁止写"对每条请求都命中"的规则**（恒真正则、`unconditionalMatch` 滥用）。规则集里存在这种规则时，预筛的候选集永远是全集，低配机器上会直接把吞吐拖垮。确实需要"永远记录"的规则请用 `action: log` 且放进独立的低优先文件，并在 `meta` 里标注。
11. **单条规则的字面量数 ≤ 64**。`pmFromFile` 加载的词表除外（走独立大词表通道）。

### 9.3 反例（会被 CI 拒绝的写法）

```yaml
# 拒绝：宽泛正则，误报必然爆炸
operator: { name: regex, params: { pattern: ".*select.*" } }

# 拒绝：没有负样本
- id: SQLI-4900
  # ... 无 test 段

# 拒绝：只查 ARGS_GET，攻击者换成 POST 就绕过
targets: [{ collection: ARGS_GET }]

# 拒绝：PCRE 特性（RE2 不支持）
operator: { name: regex, params: { pattern: "(?<=union)\\s+select" } }

# 拒绝：message 里带 payload 样例，会被回显
message: "命中注入: 1' union select 1,2--"
```

---

## 10. 校验与离线测试

### 10.1 加载期校验（`donothack` 启动与 reload 时）

1. YAML 语法。
2. 必填字段齐全。
3. `id` 全局唯一（重复则拒绝整批）。
4. `phase` 合法（1–4）。
5. `category` 在 `scoring.categories` 里存在（否则拒绝，避免命中加 0 分的静默失效）。
6. `operator.name` 与 `transforms[*]` 已注册（未知名称 → 报错并给出最接近的候选名）。
7. `regex` 能被 RE2 编译。
8. `pm` 的模式数不超上限（默认 10000）。
9. 组合算子深度 ≤ 4。
10. 正负样本非空。
11. 正样本确实会被本条规则命中（**自测**）。
12. 负样本确实不会被本条规则命中（**自测**）。
13. 统计"无预筛规则"（字面量 < 3 字节或不存在）占比，超过 20% 输出告警 —— 这直接决定低配机器上的吞吐。

11、12 两条是重点：规则改了但样本没跟上，加载直接失败，逼作者维护样本。

13 是性能向的校验：预筛覆盖率是「规则集好不好」的硬指标，不是建议。设计动机见 `docs/PERFORMANCE.md` §4。

### 10.2 CLI

```bash
# 校验规则集（不启动服务）
donothack rules check -d ./rules

# 跑全部内置样本，输出矩阵
donothack rules test -d ./rules

# 用一条真实原始请求离线跑规则，看命中链路
donothack test -r testdata/req/sqli-json.http -d ./rules

# 单条规则即时验证（调整规则时最快）
donothack rules eval -d ./rules \
  --rule SQLI-942100 \
  --value "1' union/**/select 1,2--"

# 输出命中的变换后值与算子明细（调误报时用）
donothack test -r req.http -d ./rules -v
```

`donothack test -r` 输出示例：

```
tx: offline
phase2 ───────────────────────────────────────────────
  rule SQLI-942100  ARGS:user
    transforms: removeComments,urlDecode,compressWhitespace,lowercase
    before: "admin'/**/UNION/**/SELECT/**/password/**/FROM/**/users"
    after:  "admin' union select password from users"
    operator: detectSQLi → MATCH (fingerprint: union select)
    score: +5 (category sqli) → total 5
verdict: BLOCK (threshold 5, mode block)
```

---

## 11. 与 ModSecurity SecRules 的兼容层（P5 预留）

**范围（初版）**：只支持可映射到本 DSL 的子集。

| SecRules | 映射 |
| --- | --- |
| `SecRule ARGS "@rx pattern"` | `targets: [ARGS]`, `operator: regex` |
| `@pm` / `@pmFromFile` | `operator: pm` / `pmFromFile` |
| `@detectSQLi` / `@detectXSS` | `operator: detectSQLi` / `detectXSS` |
| `@contains` / `@streq` / `@beginsWith` | 对应算子 |
| `t:lowercase` 等 | `transforms` |
| `id:` / `msg:` / `severity:` / `tag:` | 对应字段 |
| `phase:1..4` | `phase`（3/4 响应侧本轮不实现，遇到即报错退出） |
| `SecAction` / `setvar` 分数操作 | **不支持**（CRS 的评分体系与自己不同，强行映射会出隐性错误） |
| `chain` | 支持（映射为本 DSL 的 `chain`） |
| `SecRuleUpdateTargetById` | 支持 |
| 宏展开 `%{TX.0}` | **不支持** |

**明确不支持 CRS 的异常评分文件**（`REQUEST-949-BLOCKING-EVALUATION.conf` 之类）。想用 CRS 就要用 CRS 的整套评分逻辑，那等于自研引擎白写。兼容层的定位是"能把 CRS 里大多数单条检测规则搬过来复用"，不是"变成 ModSecurity"。

未支持的语法在导入时**必须报错退出**，不允许静默忽略 —— 静默忽略等同于规则没加载，是最危险的失败模式。

---

## 12. 待确认

- [ ] 集合命名是否保留 ModSecurity 风格（`ARGS`、`REQUEST_HEADERS`）？好处是迁移心智成本低，坏处是与 Go 命名习惯不同。
- [ ] 变换命名是否保留驼峰（`urlDecode`）而不是蛇形（`url_decode`）？同上，为兼容 SecRules 习惯。
- [ ] `test` 段是否强制必填（我倾向强制，但会让老规则迁移麻烦）。
- [ ] `score` 默认取类目分 vs 强制每条显式写。
- [ ] 是否需要 `SecRule` 之外的 Snort/Suricata 风格规则导入（暂定不做）。

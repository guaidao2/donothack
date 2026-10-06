# testdata/corpus —— 端到端回归语料

给"规则集 + 解析层"一起过一遍用的原始 HTTP 报文。正样本必须被拦（或按类目走挑战），
负样本必须一条规则都不命中。语料的期望裁决写在 `testdata/tools/check_corpus.py` 的
`MANIFEST` 里，改动语料就要同步改那里，否则脚本会报"MANIFEST 里没有"。

## 目录

```
corpus/
  positive/   26 条 —— 必须拦
  negative/   18 条 —— 必须放行，零命中
detect/      3 条 —— 弱信号，只记分不拦（见 detect/README.md）
```

## 报文格式

Burp / crackweb `scan -r` 那一类工具直接吃这个格式：请求行 + 头 + **一个空行** + 体。
文件是 UTF-8，行尾 LF。

```
POST /api/v1/auth/login HTTP/1.1
Host: shop.example.com
Content-Type: application/json
Content-Length: 64

{"username":"admin' or 1=1--","password":"whatever","remember":false}
```

两条硬要求：

1. **`Content-Length` 必须等于体的字节数**（不是字符数）。手改完体之后跑一次
   `python testdata/tools/check_corpus.py --fix`，它会重算并写回。
2. **multipart 的 boundary 大小写敏感**。语料里用的是 WebKit 风格的混合大小写
   boundary，别顺手 `lower()` —— 我们的回归脚本第一版就是这么写的，结果所有文件类
   规则全部静默不生效（这是个真踩过的坑，留给解析层实现者）。

## 期望裁决

阈值取 `engine.inbound_anomaly_threshold = 5`。左表是"期望"，右列是
`check_corpus.py -v` 的实测命中（对着当前规则集跑出来，改动规则后应以脚本输出为准）。

### positive/（必须拦）

| 文件 | 期望 | 实测命中 |
| --- | --- | --- |
| sqli-union-query.http | block | SQLI-4001（5） |
| sqli-union-post.http | block | SQLI-4001（5） |
| sqli-boolean-json.http | block | SQLI-4002（5） |
| sqli-time-blind.http | block | SQLI-4003（5） |
| xss-event-get.http | block | XSS-5002 + XSS-5005 + XSS-5006（12） |
| xss-script-json.http | block | XSS-5001 + XSS-5006（8） |
| xss-entity-encoded.http | block | XSS-5001（5，HTML 实体编码后命中） |
| rce-cmdi-get.http | block | RCE-6003 + LFI-7004（10） |
| rce-log4j-header.http | block | RCE-6009（5，载荷在自定义请求头里） |
| rce-ssti-json.http | block | RCE-6007 + RCE-6008（9） |
| rce-xxe-body.http | block | RCE-6010 + LFI-7004 + LFI-7005（15） |
| lfi-traversal-get.http | block | LFI-7002 + LFI-7004 + LFI-7006（14） |
| lfi-encoded-get.http | block | LFI-7002 + LFI-7004 + LFI-7006（14） |
| lfi-php-wrapper.http | block | LFI-7005（5） |
| rfi-ssrf-metadata.http | block | RFI-8001（5） |
| upload-webshell-magic.http | block | WS-9004（魔数）+ WS-9002 + RCE-6007（14） |
| upload-double-extension.http | block | UPLOAD-1001（5） |
| upload-filename-traversal.http | block | UPLOAD-1002 + LFI-7002 + LFI-7006（14） |
| webshell-access.http | block | WS-9005（5） |
| webshell-put-body.http | block | WS-9002 + RCE-6007 + RCE-6008（14） |
| scanner-git-config.http | block | SCAN-2003（5） |
| protocol-cl-te.http | block | PROTO-1006 + PROTO-1007（5，**只在 chain 生效时成立**） |
| protocol-crlf-param.http | block | PROTO-1004（5） |
| protocol-crlf-body.http | block | PROTO-1004（5） |
| scanner-sqlmap-ua.http | **challenge** | SCAN-2001（2）—— 扫描器类低分，按 DESIGN.md §10.2 走 JS 挑战而不是直接 403 |

### negative/（必须放行）

全部 score = 0。挑几条值得说明的：

| 文件 | 它守的是什么 |
| --- | --- |
| normal-apostrophe-text.http | 正常英文里的单引号（`It's` / `I'd`）不能被当成 SQLi |
| normal-rich-text-json.http | 富文本 `<p>` `<b>` 与 `&gt;` `&lt;` 不能被当成 XSS |
| normal-union-english.http | `the-european-union-and-its-members` 里的 union 不是 UNION 注入 |
| normal-select-word.http | `action=select` 这类业务参数名不能被关键词规则打死 |
| normal-template-text.http | `{{name}}` / `${price}` / `${HOME}` 不是模板注入 |
| normal-acme-challenge.http | `/.well-known/acme-challenge/...` 必须放行（`/.git` 才不会误伤它） |
| normal-backup-page.http | `/help/backup-and-restore-instructions` 不能命中备份文件规则 |
| normal-base64-image.http | base64 图片字段不能被当成编码载荷 |
| normal-upload-pdf.http | 正常 PDF 上传（魔数 `%PDF-1.4`、复合扩展名 `.pdf`）不能被当成 webshell |
| normal-static-asset.http | 带 Cookie / 长 hash 的静态资源请求必须零命中 |
| normal-checkout-form.http | 表单里的卡号、`12 Union Street` 这类地址必须零命中 |
| normal-xml-soap.http | 正常 SOAP 报文（无 ENTITY）不能被当成 XXE |

## 怎么跑

```bash
# 规则集自检（结构 + 预筛体检 + 正负样本自测 + 跨规则误报）
python testdata/tools/check_rules.py

# 语料端到端回归（自己解析报文 → 拆集合 → 跑全部规则）
python testdata/tools/check_corpus.py -v
python testdata/tools/check_corpus.py --fix   # 顺带重算 Content-Length
```

两个脚本都是"规格的二次实现"，用于在 Go 引擎落地前当护栏。引擎可用之后，
最终裁决以 `donothack test -r testdata/corpus/positive/xxx.http -d ./rules` 为准 ——
那时这两个脚本退化成快速回归（不依赖编译、不依赖构建）。

## 与 internal/rules 现状有关的两个坑（2026-10-06 核对源码）

1. **`chain` 目前是"存了但没人读"**：`internal/rules/load.go` 把 `chain` 存进
   `CompiledRule.Chain`，但全仓库没有任何地方读它。于是 PROTO-1007（"请求带
   Content-Length 时 +1 分"）会在**每个带 Content-Length 的请求**上命中 ——
   本地用 `check_corpus.py` 打开 chain 语义之前就是这个现象：全部 17 条负样本
   都被加 1 分（因为大多是 POST）。1 分不会直接导致拦截，但会把其它规则的
   有效阈值从 5 拉到 4。**chain 要么按  实现，要么这两条规则
   得换写法**；`check_corpus.py` 里已按"前置命中才评估后续"实现了 chain。

2. **预筛字面量是"前缀"而不是"最长字面量子串"**：`load.go:extractLiterals` 对
   regex 用 `re.LiteralPrefix()`，所以 `\bunion\b...`、`<script|</script`、
   `['")\]]...` 这类"不以字面量开头"的正则一条都进不了预筛，变成**每请求评估**。
   按  的说法应该是"提取最长字面量子串"，那时规则集里
   无预筛占比 18.6%，按当前前缀语义是 33.9%。两处都可复现：

   ```
   python testdata/tools/check_rules.py     # 两个口径的占比都打印
   ```

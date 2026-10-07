# detect：单一弱信号用例（设计上只记分、不拦截）

这些报文的攻击特征**真的命中了规则**，但按设计**不会拦截** ——
它们的分数低于阈值（5），只有和其他信号叠加才可能触发拦截。

* `scanner-sqlmap-ua.http` —— 靠 User-Agent 识别 sqlmap，2 分（`SCAN-2001`）。
  理由：UA 可以随意伪造，拿它做拦截条件是典型的误报源。
  它只用于**记分叠加**与事后取证，不单独立案。
* `sqli-single-quote-probe.http` —— `?q='`，值**本身就是**一个引号，2 分（`SQLI-4011`）。
  理由：这是错误型注入最典型的探测形态，值得记录；但搜索框里搜一个引号字符
  是正常行为，它单独就够阈值的话就成了"一个单引号封站"。
  对照：`O'Brien` / `it's` / `Rock'n'Roll` / `Levi's` / `The '80s` 这类
  **根本不命中**（0 分）—— 只有"整值就是引号"或"数字后紧跟引号"才认。
* `sqli-base64-json-quote.http` —— 上面那条的编码形态：`base64({"id":"'"})`。
  展开后内层值是同一个引号，所以同样是 2 分。
  （对照：`positive/sqli-base64-json-union.http` 与 `positive/sqli-base64-json-boolean.http`
  展开后是 `union select` / 布尔比较 —— 那是强特征，**仍然会被拦**。）

判据是"**不得被拦截**"，但离线能看到确切的命中链路：

```bash
dist/donothack.exe test -r testdata/corpus/detect/scanner-sqlmap-ua.http -d rules
# 期望：命中 SCAN-2001，分数 2，裁决 log

dist/donothack.exe test -r testdata/corpus/detect/sqli-single-quote-probe.http -d rules
# 期望：命中 SQLI-4011，分数 2，裁决 log
```

`scripts/acceptance.py` 对 `detect/` 的判据是：**不得被拦截**（状态码不是 403）。

> **为什么要专门有这一类**：WAF 的误报代价常常高于漏报。凡是"正常业务里
> 长得一模一样"的弱信号（UA 指纹、单独引号、裸算术表达式），一律走
> "记分但不单独立案" —— 它们能与其他信号叠加触发拦截，但不会自己把站封了。

* `rce-newline-separator-weak.http` —— 换行分隔 + 裸命令名（`?host=127.0.0.1%0aid`），
  4 分（`RCE-6001`）。理由：`\n` + 命令名是真实攻击形态（实测曾整条漏检 ——
  规则链里的 compressWhitespace 把换行折成了空格），但"换行后跟一个词"在多行文本里
  也可能出现，所以按弱信号处理：记分叠加，不单独立案。
  带参数的形态（`%0acat /etc/passwd`）会叠上 `RCE-6003`，分数够高、照常拦。

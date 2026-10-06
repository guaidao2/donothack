# detect：单一弱信号用例（设计上只记分、不拦截）

这些报文的攻击特征是**真的命中了规则**，但按设计**不会拦截**：

* `scanner-sqlmap-ua.http` —— 靠 User-Agent 识别 sqlmap，2 分（低于阈值 5）。
  理由：UA 可以随意伪造，拿它做拦截条件是典型的误报源。它只用于**记分叠加**
  与事后取证，不单独立案。
* 这类用例的正确验收方式是**离线看命中链路**，而不是看状态码：

```bash
dist/donothack.exe test -r testdata/corpus/detect/scanner-sqlmap-ua.http -d rules
# 期望：命中 SCAN-2001，分数 2，裁决 log
```

`scripts/acceptance.py` 对 `detect/` 的判据是：**不得被拦截**（状态码不是 403）。

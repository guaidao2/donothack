"""规则集自审：机械化查几类结构性缺陷。

查什么（都是本项目真实栽过的坑，改成机器查）：
  A. **模式被自己的变换链毁掉** —— 链里有 normalizePath 却写 `//`/`://`；
     链里有 compressWhitespace 却写连续空格/Tab；链里删注释却匹配 `/*`。
  B. **编码对不上** —— 链里有 urlDecode 却用 `%2f` 这类编码字面量（解码后不可能命中）。
  C. **大小写对不上** —— 链里有 lowercase 却写大写字母（永远配不上）。
  D. **目标集合缺面** —— 命令/路径类模式却没看 REQUEST_URI / REQUEST_HEADERS / REQUEST_COOKIES。
  E. **分值政策** —— critical/high 却低于阈值 5（单独不能拦）的，列出来确认是不是有意为之。
  F. **重复模式** —— 同一条串散在多条规则里（分数虚高，且改一处漏一处）。
"""

from __future__ import annotations

import pathlib
import re
import sys
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = pathlib.Path(r"D:\编程\donothack\rules")

# 手工解析（规则文件结构固定，不引 yaml 依赖）
rules: list[dict] = []
for f in sorted(ROOT.glob("*.yaml")):
    text = f.read_text(encoding="utf-8")
    for blk in re.split(r"\n  - id: ", text)[1:]:
        lines = blk.splitlines()
        rid = lines[0].strip()
        head = blk.split("test:")[0]
        op = {}
        for k in ("score", "severity", "category"):
            m = re.search(rf"^\s+{k}:\s*(\S+)", head, re.M)
            op[k] = m.group(1) if m else ""
        tr = re.search(r"transforms:\n((?:\s+- \w+\n)+)", head)
        op["transforms"] = re.findall(r"- (\w+)", tr.group(1)) if tr else []
        op["targets"] = re.findall(r"collection: (\w+)", head)
        pats = re.findall(r'^\s+- "(.*)"$', head, re.M)
        op["patterns"] = pats
        op["id"], op["file"] = rid, f.name
        rules.append(op)

print(f"规则总数：{len(rules)}\n")

# A/B/C：模式 vs 变换链
issues: list[str] = []
for r in rules:
    tr = r["transforms"]
    for p in r["patterns"]:
        if "normalizePath" in tr or "normalizePathWin" in tr:
            if "//" in p or "://" in p or "/./" in p:
                issues.append(f"A {r['id']}（{r['file']}）：链里有 normalizePath，但模式含 `{p}` —— 会被折成单个斜杠")
        if "compressWhitespace" in tr and ("  " in p or "\t" in p):
            issues.append(f"A {r['id']}（{r['file']}）：链里有 compressWhitespace，但模式含连续空白 `{p}`")
        if ("removeComments" in tr or "replaceComments" in tr) and ("/*" in p or "--" in p or "<!--" in p):
            issues.append(f"A {r['id']}（{r['file']}）：链里删/替注释，但模式含注释标记 `{p}`")
        # 编码字面量只有在**解码两次以上**时才是死模式：
        # 只解一次的话，`%252e%252e` 解出来正好是 `%2e%2e` —— 那是专门用来兜双重编码的，别误报。
        decodes = sum(1 for x in tr if x in ("urlDecode", "doubleUrlDecode", "urlDecodeUni"))
        if decodes >= 2 and re.search(r"%[0-9a-fA-F]{2}", p):
            issues.append(
                f"B {r['id']}（{r['file']}）：链里有 {decodes} 次解码，但模式是编码形态 `{p}` —— 解完两遍配不上"
            )
        if "lowercase" in tr and re.search(r"[A-Z]", p):
            issues.append(f"C {r['id']}（{r['file']}）：链里有 lowercase，但模式含大写 `{p}`")

print("=== A/B/C 模式与变换链冲突 ===")
if issues:
    for i in issues:
        print("  " + i)
else:
    print("  无")

# D：目标集合缺面
print("\n=== D 目标集合（命令/路径类却没看 URI/头/Cookie）===")
CMD_ISH = re.compile(r"(cat|whoami|/etc/|/bin/|\.\./|cmd|powershell|shell|bash|union|select)")
for r in rules:
    if not any(CMD_ISH.search(p) for p in r["patterns"]):
        continue
    missing = [t for t in ("REQUEST_URI", "REQUEST_HEADERS", "REQUEST_COOKIES") if t not in r["targets"]]
    if missing and "ARGS" in r["targets"]:
        print(f"  {r['id']}（{r['file']}）：看 {','.join(r['targets'])}，可补 {','.join(missing)}")

# E：分值政策
print("\n=== E 低分但高危（低于阈值 5 = 单独不能拦）===")
for r in rules:
    if r["severity"] in ("critical", "high") and r["score"].isdigit() and int(r["score"]) < 5:
        print(f"  {r['id']}（{r['file']}）：{r['severity']} / {r['score']} 分 / {r['category']}")

# F：重复模式
print("\n=== F 同一条串散在多条规则里（前 12 组）===")
where: dict[str, list[str]] = defaultdict(list)
for r in rules:
    for p in r["patterns"]:
        where[p].append(r["id"])
dups = {p: ids for p, ids in where.items() if len(ids) > 1}
for p, ids in list(sorted(dups.items(), key=lambda kv: -len(kv[1])))[:12]:
    print(f"  `{p}` -> {', '.join(ids)}")
print(f"  重复模式总数：{len(dups)}")

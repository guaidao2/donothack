#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_rules.py —— rules/*.yaml 的离线自检（在 Go 加载器落地之前先当护栏用）。

它做四件事：
  1. 结构校验：必填字段、枚举取值、集合名/变换名/算子名是否都在 docs/RULES.md 的清单里、
     RESPONSE_* 一律拒绝、id 唯一且段位与类目对上。
  2. 预筛体检：算每条规则有没有 >=3 字节的字面量（pm 模式 / regex 最长字面子串 /
     contains 的 value），统计"无预筛"占比（规格要求 <=20%），并检查单条字面量数 <=64。
  3. 样本自测：用本脚本实现的变换链 + 算子，把 test.positive 全部跑一遍必须命中、
     test.negative 全部跑一遍必须不命中 —— 这正是加载器 §10.1 第 11/12 条的语义。
     语义算子（detectSQLi / detectXSS / detectPathTraversal / isWebshellContent /
     containsShellChars）没有权威实现，跳过匹配但会列出来。
  4. RE2 兼容性：拒绝反向引用与环视（Python re 支持而 RE2 不支持）。

⚠ 本脚本是"规格的二次实现"，不是加载器：urlDecode 是否处理 '+'、removeComments
   是删除还是替换为空格、not/anyOf 的 params 嵌套形状，这些都按 docs/RULES.md 的
   字面描述猜的。凡是猜的地方都写在该变换/算子的注释里。

用法：
    python testdata/tools/check_rules.py [--rules rules]
"""
import argparse
import os
import re
import sys
import unicodedata
from urllib.parse import unquote

try:
    import yaml
except ImportError:
    print("需要 PyYAML：python -m pip install pyyaml")
    sys.exit(2)

# ── docs/RULES.md §5.1 的集合清单（请求侧 + 派生） ────────────────────────
REQUEST_COLLECTIONS = {
    "ARGS", "ARGS_GET", "ARGS_POST", "ARGS_JSON", "ARGS_XML", "ARGS_NAMES",
    "REQUEST_URI", "REQUEST_PATH", "REQUEST_METHOD", "REQUEST_PROTOCOL",
    "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES", "REQUEST_COOKIES",
    "REQUEST_COOKIES_NAMES", "REQUEST_BODY", "FILES", "FILES_NAMES",
    "FILES_SIZES", "FILES_MAGIC", "REMOTE_ADDR", "TX",
    "ARGS_COUNT", "REQUEST_URI_LENGTH", "REQUEST_BODY_LENGTH",
}
RESPONSE_COLLECTIONS = {
    "RESPONSE_STATUS", "RESPONSE_HEADERS", "RESPONSE_BODY", "RESPONSE_CONTENT_TYPE",
}

# ── docs/RULES.md §6 ────────────────────────────────────────────────────
TRANSFORMS = {
    "none", "lowercase", "uppercase", "urlDecode", "urlDecodeUni",
    "doubleUrlDecode", "htmlEntityDecode", "jsDecode", "base64Decode",
    "base64DecodeExt", "sqlHexDecode", "cssDecode", "removeComments",
    "removeNulls", "compressWhitespace", "removeWhitespace", "trim",
    "normalizePath", "normalizePathWin", "replaceComments", "length",
    "hexEncode", "hexDecode", "sha1", "md5", "cmdLine", "utf8ToUnicode",
    "escapeSeqDecode",
}

# ── docs/RULES.md §7 ────────────────────────────────────────────────────
OPERATORS = {
    "eq", "equals", "eqIgnoreCase", "contains", "containsAny", "startsWith",
    "endsWith", "regex", "pm", "pmFromFile", "gt", "ge", "lt", "le", "within",
    "validateByteRange", "detectSQLi", "detectXSS", "detectPathTraversal",
    "containsShellChars", "isWebshellContent", "entropy", "luhn", "verifyCC",
    "isValidJWT", "ipMatch", "ipMatchFromFile", "rblLookup", "geoLookup",
    "allOf", "anyOf", "not", "unconditionalMatch",
}
SEMANTIC_OPERATORS = {
    "detectSQLi", "detectXSS", "detectPathTraversal", "containsShellChars",
    "isWebshellContent", "entropy", "luhn", "verifyCC", "isValidJWT",
    "ipMatch", "ipMatchFromFile", "rblLookup", "geoLookup",
}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
# docs/DESIGN.md §10.1 的 scoring.categories
CATEGORIES = {"sqli", "xss", "rce", "lfi", "rfi", "webshell", "scanner",
              "protocol", "upload"}
ID_PREFIX_BY_CATEGORY = {
    "protocol": "PROTO", "scanner": "SCAN", "sqli": "SQLI", "xss": "XSS",
    "rce": "RCE", "lfi": "LFI", "rfi": "RFI", "webshell": "WS",
    "upload": "UPLOAD",
}

errors = []
warnings = []
notes = []


def err(msg):
    errors.append(msg)


def warn(msg):
    warnings.append(msg)


# ── 变换链实现（按 docs/RULES.md §6 的字面描述；猜的地方标注了） ──────────
_HTML_NAMED = {
    "lt": "<", "gt": ">", "quot": '"', "apos": "'", "amp": "&",
    "colon": ":", "tab": "\t", "newline": "\n", "sol": "/", "num": "#",
    "period": ".", "comma": ",", "lpar": "(", "rpar": ")",
}


def t_url_decode(v):
    # 只解 %XX；不把 '+' 当空格（RULES.md 没写，ModSecurity 的 t:urlDecode 也不转）
    out = []
    i = 0
    while i < len(v):
        c = v[i]
        if c == "%" and i + 2 < len(v) + 1 and len(v[i + 1:i + 3]) == 2:
            try:
                out.append(chr(int(v[i + 1:i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(c)
        i += 1
    return "".join(out)


def t_url_decode_uni(v):
    v = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), v)
    return t_url_decode(v)


def t_html_entity_decode(v):
    def numeric(m):
        body = m.group(1)
        try:
            if body[:1] in ("x", "X"):
                return chr(int(body[1:], 16))
            return chr(int(body))
        except (ValueError, OverflowError):
            return m.group(0)

    v = re.sub(r"&#(x[0-9a-fA-F]+|[0-9]+);?", numeric, v)
    for name, ch in _HTML_NAMED.items():
        v = re.sub(r"&" + name + r";", ch, v, flags=re.IGNORECASE)
    return v


def t_js_decode(v):
    v = re.sub(r"\\u\{([0-9a-fA-F]{1,6})\}", lambda m: chr(int(m.group(1), 16)), v)
    v = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), v)
    v = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), v)
    return v


def t_remove_comments(v):
    # RULES.md 只说"去"，此处按删除处理（与 replaceComments 区分）
    v = re.sub(r"/\*.*?\*/", "", v, flags=re.S)
    v = re.sub(r"<!--.*?-->", "", v, flags=re.S)
    v = re.sub(r"--", "", v)
    v = v.replace("#", "")
    return v


def t_replace_comments(v):
    # RULES.md §6：注释替换为单个空格（避免拼接绕过）
    v = re.sub(r"/\*.*?\*/", " ", v, flags=re.S)
    v = re.sub(r"<!--.*?-->", " ", v, flags=re.S)
    v = re.sub(r"--", " ", v)
    v = v.replace("#", " ")
    return v


def t_sql_hex_decode(v):
    def hexstr(h):
        if len(h) % 2:
            h = h + "0"
        try:
            return bytes.fromhex(h).decode("latin-1")
        except ValueError:
            return None

    def rep0x(m):
        d = hexstr(m.group(1))
        return d if d is not None else m.group(0)

    v = re.sub(r"\b0x([0-9a-fA-F]{2,})", rep0x, v)

    def repx(m):
        d = hexstr(m.group(1))
        return d if d is not None else m.group(0)

    v = re.sub(r"\bX'([0-9a-fA-F]{2,})'", repx, v, flags=re.IGNORECASE)
    return v


def t_css_decode(v):
    return re.sub(r"\\([0-9a-fA-F]{1,6})\s?",
                  lambda m: chr(int(m.group(1), 16)), v)


def t_escape_seq_decode(v):
    mapping = {"n": "\n", "t": "\t", "r": "\r", "0": "\x00", "\\": "\\"}
    return re.sub(r"\\(.)", lambda m: mapping.get(m.group(1), m.group(1)), v)


def t_normalize_path(v, win=False):
    if win:
        v = v.replace("\\", "/")
    v = v.replace("\x00", "")
    v = re.sub(r"/+", "/", v)
    while re.search(r"/\.\.?/", v):
        v = re.sub(r"/\.\.?/", "/", v)
    return v


def _b64(v, ext=False):
    import base64
    s = v.strip()
    if ext:
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=not ext).decode("utf-8", "replace")
    except Exception:
        return v


def apply_chain(value, chain):
    v = value
    for name in chain:
        if name == "none":
            pass
        elif name == "lowercase":
            v = v.lower()
        elif name == "uppercase":
            v = v.upper()
        elif name == "urlDecode":
            v = t_url_decode(v)
        elif name == "urlDecodeUni":
            v = t_url_decode_uni(v)
        elif name == "doubleUrlDecode":
            v = t_url_decode(t_url_decode(v))
        elif name == "htmlEntityDecode":
            v = t_html_entity_decode(v)
        elif name == "jsDecode":
            v = t_js_decode(v)
        elif name == "base64Decode":
            v = _b64(v, ext=False)
        elif name == "base64DecodeExt":
            v = _b64(v, ext=True)
        elif name == "sqlHexDecode":
            v = t_sql_hex_decode(v)
        elif name == "cssDecode":
            v = t_css_decode(v)
        elif name == "removeComments":
            v = t_remove_comments(v)
        elif name == "replaceComments":
            v = t_replace_comments(v)
        elif name == "removeNulls":
            v = v.replace("\x00", "")
        elif name == "compressWhitespace":
            v = re.sub(r"\s+", " ", v)
        elif name == "removeWhitespace":
            v = re.sub(r"\s+", "", v)
        elif name == "trim":
            v = v.strip()
        elif name == "normalizePath":
            v = t_normalize_path(v, win=False)
        elif name == "normalizePathWin":
            v = t_normalize_path(v, win=True)
        elif name == "length":
            v = str(len(v))
        elif name == "hexDecode":
            try:
                v = bytes.fromhex(v).decode("latin-1")
            except ValueError:
                pass
        elif name == "escapeSeqDecode":
            v = t_escape_seq_decode(v)
        elif name in ("hexEncode", "sha1", "md5", "cmdLine", "utf8ToUnicode"):
            pass  # 本规则集未使用
        else:
            pass
    return v


# ── 算子实现 ────────────────────────────────────────────────────────────
def op_match(op, value):
    """返回 True/False；语义算子返回 None 表示"无法验证"。"""
    name = op.get("name")
    params = op.get("params") or {}
    if name in SEMANTIC_OPERATORS:
        return None
    if name in ("eq", "equals"):
        return value == params.get("value")
    if name == "eqIgnoreCase":
        return value.lower() == str(params.get("value", "")).lower()
    if name == "contains":
        return str(params.get("value", "")) in value
    if name == "containsAny":
        return any(str(v) in value for v in (params.get("values") or []))
    if name == "startsWith":
        return value.startswith(str(params.get("value", "")))
    if name == "endsWith":
        return value.endswith(str(params.get("value", "")))
    if name == "regex":
        return re.search(params["pattern"], value) is not None
    if name == "pm":
        pats = params.get("patterns") or []
        hits = [p for p in pats if p in value]
        if params.get("match_all"):
            return len(hits) == len(pats) and bool(pats)
        return bool(hits)
    if name in ("gt", "ge", "lt", "le"):
        try:
            lhs = float(value)
            rhs = float(params.get("value"))
        except (TypeError, ValueError):
            return False
        return {"gt": lhs > rhs, "ge": lhs >= rhs,
                "lt": lhs < rhs, "le": lhs <= rhs}[name]
    if name == "within":
        try:
            lhs = float(value)
        except (TypeError, ValueError):
            return False
        return float(params.get("min", 0)) <= lhs <= float(params.get("max", 0))
    if name == "validateByteRange":
        rng = str(params.get("range", ""))
        lo, _, hi = rng.partition("-")
        lo, hi = int(lo), int(hi)
        return any(b < lo or b > hi for b in value.encode("latin-1", "replace"))
    if name == "not":
        inner = op_match(params.get("operator") or {}, value)
        return None if inner is None else (not inner)
    if name == "anyOf":
        subs = [op_match(o, value) for o in (params.get("operators") or [])]
        if any(s is None for s in subs):
            return None
        return any(subs)
    if name == "allOf":
        subs = [op_match(o, value) for o in (params.get("operators") or [])]
        if any(s is None for s in subs):
            return None
        return all(subs)
    if name == "unconditionalMatch":
        return True
    return None


# ── 预筛字面量提取 ──────────────────────────────────────────────────────
RE2_BAD = [
    (r"\(\?=", "lookahead (?="), (r"\(\?!", "negative lookahead (?!"),
    (r"\(\?<=", "lookbehind (?<="), (r"\(\?<!", "negative lookbehind (?<!"),
    (r"\\[1-9]", "backreference \\1"),
]


def literal_runs(pattern):
    """粗取 regex 里的字面量子串（>=3 字节的那些）。

    刻意跳过字符类 [...] 的内容：`[0-9]` 里的 "0-9" 不是字面量，
    把它算进去会让"无预筛"统计偏乐观（PROTO-1007 就是这么被抓出来的）。
    """
    runs = []
    cur = []
    i = 0
    in_class = False
    while i < len(pattern):
        c = pattern[i]
        if in_class:
            if c == "\\":
                i += 2
                continue
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            if cur:
                runs.append("".join(cur))
                cur = []
            in_class = True
            i += 2 if i + 1 < len(pattern) and pattern[i + 1] == "^" else 1
            continue
        if c == "\\":
            nxt = pattern[i + 1] if i + 1 < len(pattern) else ""
            if nxt in "dDsSwWbBAZz":
                if cur:
                    runs.append("".join(cur))
                    cur = []
                i += 2
                continue
            if nxt == "x" and i + 4 <= len(pattern):
                try:
                    cur.append(chr(int(pattern[i + 2:i + 4], 16)))
                    i += 4
                    continue
                except ValueError:
                    pass
            cur.append(nxt)
            i += 2
            continue
        if c.isalnum() or c in " _-":
            cur.append(c)
            i += 1
            continue
        if cur:
            runs.append("".join(cur))
            cur = []
        i += 1
    if cur:
        runs.append("".join(cur))
    return [r for r in runs if len(r) >= 3]


def literal_prefix(pattern):
    """近似 Go regexp 的 LiteralPrefix()：**必须**是匹配开头的固定字符串。

    这是加载器（internal/rules/load.go extractLiterals）实际用的语义 ——
    只认前缀，不认"中间的字面量"。顶层 `|` 的每个分支都要有共同前缀才算。
    与 docs/PERFORMANCE.md §4 写的"regex 提取的最长字面量子串"不一致，
    两个数都报出来，好知道该修哪边。
    """
    # 按顶层 | 切分
    branches, depth, cur = [], 0, []
    in_class = False
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\":
            cur.append(pattern[i:i + 2])
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
            cur.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            cur.append(c)
            i += 1
            continue
        if c == "(":
            depth += 1
            cur.append(c)
            i += 1
            continue
        if c == ")":
            depth -= 1
            cur.append(c)
            i += 1
            continue
        if c == "|" and depth == 0:
            branches.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    branches.append("".join(cur))

    def lead(branch):
        out = []
        i = 0
        while i < len(branch):
            c = branch[i]
            if c == "\\":
                nxt = branch[i + 1] if i + 1 < len(branch) else ""
                if nxt in "dDsSwWbBAZz" or not nxt:
                    break
                out.append(nxt)
                i += 2
                continue
            if c.isalnum() or c in " _-":
                out.append(c)
                i += 1
                continue
            break
        return "".join(out)

    leads = [lead(b) for b in branches]
    if not leads:
        return ""
    common = leads[0]
    for s in leads[1:]:
        n = 0
        while n < len(common) and n < len(s) and common[n] == s[n]:
            n += 1
        common = common[:n]
    return common


def rule_prefix_literals(rule):
    """加载器语义下这条规则能进预筛的字面量。"""
    op = rule.get("operator") or {}
    params = op.get("params") or {}
    name = op.get("name")
    if name in SEMANTIC_OPERATORS:
        return []
    if name == "pm":
        return [p for p in (params.get("patterns") or []) if len(p) >= 3]
    if name in ("contains", "eq", "equals", "eqIgnoreCase", "startsWith", "endsWith"):
        v = str(params.get("value", ""))
        return [v] if len(v) >= 3 else []
    if name == "containsAny":
        return [v for v in (params.get("values") or []) if len(str(v)) >= 3]
    if name == "regex":
        p = literal_prefix(params.get("pattern", ""))
        return [p] if len(p) >= 3 else []
    return []  # 取反 / 数值 / 字节范围 / 组合算子：加载器都不提取（default 分支）


def rule_literals(rule):
    """返回该规则里"能进预筛自动机"的字面量列表。

    `not` 子树里的字面量**不算**：预筛是"命中任一候选字面量才执行规则"，
    而取反规则的触发条件恰恰是"这些字面量都不出现"，拿它做候选只会漏检。
    正确做法是把 not 规则整个归入"无预筛、直接执行"。
    """
    op = rule.get("operator") or {}

    def walk(o):
        out = []
        name = o.get("name")
        params = o.get("params") or {}
        if name == "pm":
            out += [p for p in (params.get("patterns") or []) if len(p) >= 3]
        elif name == "regex":
            out += literal_runs(params.get("pattern", ""))
        elif name in ("contains", "eq", "equals", "eqIgnoreCase",
                      "startsWith", "endsWith"):
            v = str(params.get("value", ""))
            if len(v) >= 3:
                out.append(v)
        elif name == "containsAny":
            out += [v for v in (params.get("values") or []) if len(str(v)) >= 3]
        elif name == "not":
            pass  # 取反：不可用于预筛
        elif name in ("anyOf", "allOf"):
            for s in (params.get("operators") or []):
                out += walk(s)
        return out

    return walk(op)


def count_literals_syntactic(rule):
    """字面量个数（只数 pm/contains 这类显式列出的，用于 <=64 的体检）。"""
    op = rule.get("operator") or {}
    params = op.get("params") or {}
    if op.get("name") == "pm":
        return len(params.get("patterns") or [])
    if op.get("name") == "containsAny":
        return len(params.get("values") or [])
    if op.get("name") == "regex":
        return len(literal_runs(params.get("pattern", "")))
    return 1 if rule_literals(rule) else 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", "rules"))
    args = ap.parse_args()
    rules_dir = os.path.abspath(args.rules)

    if not os.path.isdir(rules_dir):
        print("找不到规则目录：%s" % rules_dir)
        return 2

    files = sorted(f for f in os.listdir(rules_dir) if f.endswith(".yaml"))
    if not files:
        print("规则目录里没有 .yaml")
        return 2

    all_ids = {}
    total_rules = 0
    no_prefilter = []
    no_prefix = []
    per_file = []
    unverifiable = []
    cat_count = {}

    for fn in files:
        path = os.path.join(rules_dir, fn)
        with open(path, "r", encoding="utf-8") as fh:
            try:
                doc = yaml.safe_load(fh)
            except yaml.YAMLError as e:
                err("%s: YAML 解析失败: %s" % (fn, e))
                continue
        if not isinstance(doc, dict):
            err("%s: 顶层不是映射" % fn)
            continue
        if doc.get("version") != 1:
            err("%s: version 必须是 1（当前 %r）" % (fn, doc.get("version")))
        meta = doc.get("meta") or {}
        for k in ("name", "author", "category"):
            if not meta.get(k):
                err("%s: meta.%s 缺失" % (fn, k))
        if meta.get("category") not in CATEGORIES:
            err("%s: meta.category=%r 不在 scoring.categories 里" % (fn, meta.get("category")))
        rules = doc.get("rules")
        if not isinstance(rules, list) or not rules:
            err("%s: rules 为空" % fn)
            continue
        per_file.append((fn, len(rules)))
        total_rules += len(rules)

        for idx, rule in enumerate(rules):
            where = "%s[%d]" % (fn, idx)
            if not isinstance(rule, dict):
                err("%s: 规则不是映射" % where)
                continue
            rid = rule.get("id")
            where = "%s(%s)" % (fn, rid)
            if not rid:
                err("%s: id 缺失" % where)
            elif rid in all_ids:
                err("%s: id 重复（另见 %s）" % (where, all_ids[rid]))
            else:
                all_ids[rid] = where
            if rule.get("phase") not in (1, 2):
                err("%s: phase 必须是 1 或 2（本轮只支持请求侧）" % where)
            if rule.get("severity") not in SEVERITIES:
                err("%s: severity=%r 非法" % (where, rule.get("severity")))
            cat = rule.get("category") or meta.get("category")
            if cat not in CATEGORIES:
                err("%s: category=%r 不在 scoring.categories 里" % (where, cat))
            else:
                cat_count[cat] = cat_count.get(cat, 0) + 1
                pref = ID_PREFIX_BY_CATEGORY.get(cat)
                if pref and rid and not str(rid).startswith(pref + "-"):
                    err("%s: id 段位与类目不符（应为 %s-xxxx）" % (where, pref))
            if not isinstance(rule.get("score"), int):
                err("%s: score 必须是整数" % where)
            msg = rule.get("message")
            # 返回给用户的拦截页不回显 payload，所以 message 里不能出现引号/尖括号样例
            if not msg or not str(msg).strip():
                err("%s: message 缺失" % where)
            elif any(t in str(msg) for t in ("'", "<", ">", "%00", "--")):
                warn("%s: message 里疑似含 payload 片段，可能被回显" % where)
            targets = rule.get("targets")
            if not isinstance(targets, list) or not targets:
                err("%s: targets 缺失" % where)
            else:
                for t in targets:
                    if not isinstance(t, dict) or not t.get("collection"):
                        err("%s: target 写法不对（需要 collection）" % where)
                        continue
                    coll = t["collection"]
                    if coll in RESPONSE_COLLECTIONS:
                        err("%s: 使用了 %s —— 本轮不实现响应侧，加载器会拒绝" % (where, coll))
                    elif coll not in REQUEST_COLLECTIONS:
                        err("%s: 未知集合 %r" % (where, coll))
                    if "selector" in t and not isinstance(t["selector"], str):
                        err("%s: selector 必须是字符串" % where)
                    if "selector" in t and str(t.get("selector", "")).startswith("/") \
                            and not str(t.get("selector", "")).endswith("/"):
                        err("%s: selector 用斜杠包裹才算正则键" % where)

            chain = rule.get("transforms") or []
            for tn in chain:
                if tn not in TRANSFORMS:
                    err("%s: 未知变换 %r" % (where, tn))
            if "length" in chain[:-1]:
                err("%s: length 改变语义，必须放在链尾" % where)

            op = rule.get("operator")
            if not isinstance(op, dict) or not op.get("name"):
                err("%s: operator 缺失或没有 name" % where)
                continue

            def check_op(o, depth=0, ctx=where):
                if depth > 4:
                    err("%s: 组合算子深度超过 4 层" % ctx)
                nm = o.get("name")
                if nm not in OPERATORS:
                    err("%s: 未知算子 %r" % (ctx, nm))
                    return
                p = o.get("params") or {}
                if nm == "regex":
                    pat = p.get("pattern")
                    if not pat:
                        err("%s: regex 缺 pattern" % ctx)
                        return
                    for bad, why in RE2_BAD:
                        if re.search(bad, pat):
                            err("%s: 用了 RE2 不支持的 %s" % (ctx, why))
                    try:
                        re.compile(pat)
                    except re.error as e:
                        err("%s: 正则编译失败: %s" % (ctx, e))
                if nm == "pm" and not (p.get("patterns")):
                    err("%s: pm 缺 patterns" % ctx)
                if nm in ("anyOf", "allOf"):
                    subs = p.get("operators") or []
                    if not subs:
                        err("%s: %s 缺 operators" % (ctx, nm))
                    for s in subs:
                        check_op(s, depth + 1, ctx)
                if nm == "not":
                    if not isinstance(p.get("operator"), dict):
                        err("%s: not 缺 params.operator" % ctx)
                    else:
                        check_op(p["operator"], depth + 1, ctx)

            check_op(op)

            # 预筛体检：没有任何 >=3 字节可用字面量的规则，都是"无预筛、直接执行"。
            # 这包括语义算子（detectSQLi 等）、纯数值/字节范围算子、以及取反规则。
            lits = rule_literals(rule)
            if not lits:
                no_prefilter.append(where)
            if not rule_prefix_literals(rule):
                no_prefix.append(where)
            if count_literals_syntactic(rule) > 64:
                err("%s: 单条字面量数 %d > 64" % (where, count_literals_syntactic(rule)))

            test = rule.get("test") or {}
            pos = test.get("positive") or []
            neg = test.get("negative") or []
            if not pos:
                err("%s: test.positive 为空" % where)
            if len(neg) < 2:
                err("%s: test.negative 少于 2 条" % where)

            if op.get("name") in SEMANTIC_OPERATORS:
                unverifiable.append("%s (%s)" % (where, op.get("name")))
            else:
                for sample in pos:
                    if not isinstance(sample, str):
                        err("%s: 正样本必须是字符串" % where)
                        continue
                    v = apply_chain(sample, chain)
                    r = op_match(op, v)
                    if r is None:
                        unverifiable.append("%s (%s)" % (where, op.get("name")))
                        break
                    if not r:
                        err("%s: 正样本未命中: %r → 变换后 %r" % (where, sample, v))
                for sample in neg:
                    if not isinstance(sample, str):
                        err("%s: 负样本必须是字符串" % where)
                        continue
                    v = apply_chain(sample, chain)
                    r = op_match(op, v)
                    if r:
                        err("%s: 负样本命中（会误报）: %r → 变换后 %r" % (where, sample, v))

    # ── 跨规则误报体检 ─────────────────────────────────────────────────
    # 每条规则的负样本都是"正常业务流量形态"，因此它不该被**任何**规则命中。
    # 这一步抓的是"规则 A 的正常样本被规则 B 打死"这类单规则自测发现不了的问题。
    #
    # 只对"目标作用域一致"的规则两两比对：集合相同、且 selector 相同
    # （都是"整个集合"或同一个键）。把 content-encoding 的规则拿去跑 User-Agent
    # 的值、或把方法合法性规则拿去跑文件名，都只会产生噪声。
    #
    # ALLOWED_CROSS 是"有意为之"的重叠：PROTO-1006 是走私检查的前半条
    # （Transfer-Encoding 头存在，4 分 + log），它命中任何 TE 取值是设计使然，
    # 包括 PROTO-1008 视为合法的 identity。
    STRUCTURAL = {"REQUEST_METHOD", "REQUEST_PROTOCOL", "REQUEST_URI_LENGTH",
                  "REQUEST_BODY_LENGTH", "ARGS_COUNT", "REMOTE_ADDR",
                  "FILES_SIZES", "TX"}
    ALLOWED_CROSS = {("PROTO-1006", "PROTO-1008")}

    def target_scopes(rule):
        return {(t.get("collection"), t.get("selector"))
                for t in (rule.get("targets") or []) if isinstance(t, dict)}

    def rule_id_of(where):
        return where.split("(")[-1].rstrip(")")

    compiled = []
    for fn in files:
        path = os.path.join(rules_dir, fn)
        with open(path, "r", encoding="utf-8") as fh:
            try:
                doc = yaml.safe_load(fh) or {}
            except yaml.YAMLError:
                continue
        for rule in (doc.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            op = rule.get("operator") or {}
            scopes = target_scopes(rule)
            if not isinstance(op, dict) or op.get("name") in SEMANTIC_OPERATORS:
                continue
            if {c for c, _ in scopes} & STRUCTURAL:
                continue
            compiled.append(("%s(%s)" % (fn, rule.get("id")),
                             rule.get("transforms") or [], op, scopes,
                             rule_id_of("%s(%s)" % (fn, rule.get("id")))))

    cross_hits = []
    seen_pairs = set()
    for fn in files:
        path = os.path.join(rules_dir, fn)
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        for rule in (doc.get("rules") or []):
            if not isinstance(rule, dict):
                continue
            src_scopes = target_scopes(rule)
            for sample in ((rule.get("test") or {}).get("negative") or []):
                if not isinstance(sample, str):
                    continue
                for where, chain, op, scopes, rid in compiled:
                    if where.startswith(fn) and rid == rule.get("id"):
                        continue  # 自家规则已在上面单独测过
                    if not (scopes & src_scopes):
                        continue
                    if (rid, rule.get("id")) in ALLOWED_CROSS:
                        continue
                    try:
                        if op_match(op, apply_chain(sample, chain)):
                            key = (where, sample)
                            if key in seen_pairs:
                                continue
                            seen_pairs.add(key)
                            cross_hits.append(
                                "%s 会命中 %s 的负样本: %r" % (where, rule.get("id"), sample))
                    except re.error:
                        pass

    # ── 汇总 ───────────────────────────────────────────────────────────
    print("=" * 72)
    print("规则文件：%d 个，规则总数 %d" % (len(files), total_rules))
    for fn, n in per_file:
        print("  %-22s %3d 条" % (fn, n))
    print("-" * 72)
    print("类目分布：")
    for c in sorted(cat_count):
        print("  %-10s %3d 条" % (c, cat_count[c]))
    print("-" * 72)
    ratio = (len(no_prefilter) * 100.0 / total_rules) if total_rules else 0
    print("无预筛规则（按 docs 的\"最长字面量子串\"语义）：%d / %d = %.1f%%  (上限 20%%)"
          % (len(no_prefilter), total_rules, ratio))
    for w in no_prefilter:
        print("    - %s" % w)
    if ratio > 20:
        warn("无预筛占比超过 20%%，预筛自动机会退化")
    pratio = (len(no_prefix) * 100.0 / total_rules) if total_rules else 0
    print("-" * 72)
    print("无预筛规则（按加载器实际的 LiteralPrefix 前缀语义）：%d / %d = %.1f%%"
          % (len(no_prefix), total_rules, pratio))
    print("    其中目标是多值集合（ARGS/BODY/COOKIES/HEADERS 全量）的：")
    hot = 0
    for w in no_prefix:
        rid = w.split("(")[-1].rstrip(")")
        for fn2 in files:
            path2 = os.path.join(rules_dir, fn2)
            with open(path2, "r", encoding="utf-8") as fh2:
                doc2 = yaml.safe_load(fh2) or {}
            for r2 in (doc2.get("rules") or []):
                if isinstance(r2, dict) and r2.get("id") == rid:
                    colls = {t.get("collection") for t in (r2.get("targets") or [])
                             if isinstance(t, dict)}
                    if colls & {"ARGS", "REQUEST_BODY", "REQUEST_COOKIES"}:
                        hot += 1
                        print("      * %s  %s" % (w, sorted(colls)))
    if pratio > 20:
        warn("按加载器的前缀语义，无预筛占比 %.1f%% —— 这些规则每请求都会执行" % pratio)
    print("    （多值集合上的 %d 条是热路径，其余落在 REQUEST_PATH/URI/单值头等每请求一个值的地方）"
          % hot)
    if unverifiable:
        print("-" * 72)
        print("无法用本脚本验证匹配的规则（语义算子待 Go 实现）：%d 条" % len(unverifiable))
        for u in unverifiable:
            print("    - %s" % u)
    print("-" * 72)
    if cross_hits:
        print("跨规则误报 %d 处（负样本被别的规则命中）：" % len(cross_hits))
        for h in cross_hits:
            print("  X %s" % h)
            errors.append(h)
    else:
        print("跨规则误报体检：全部负样本对全部规则均未命中")
    if warnings:
        print("警告 %d 条：" % len(warnings))
        for w in warnings:
            print("  ! %s" % w)
    if errors:
        print("错误 %d 条：" % len(errors))
        for e in errors:
            print("  X %s" % e)
    else:
        print("样本自测与结构校验：全部通过")
    print("=" * 72)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

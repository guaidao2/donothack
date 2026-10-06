#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_corpus.py —— testdata/corpus/*.http 的端到端回归（Go 加载器落地前先跑这个）。

它自己解析原始 HTTP 报文、把请求拆成引擎定义的变量集合，然后把**全部规则**
跑一遍，最后按目录断言：

    positive/*.http   必须命中（多数是"总分 >= 阈值 5"）
    negative/*.http   必须一条规则都不命中（score 合计 0）

这一层抓的是规则自测抓不到的问题：请求级组合、集合选择器写错、语料与规则脱节。

注意：这是对解析层语义的一次近似实现（见下方 collections 注释），不是引擎：
   multipart 字段拆分、JSON 叶子展开、路径规范化都按  的描述写。
   真引擎上线后应以 `donothack test -r testdata/corpus/...` 为准，本脚本退居快速回归。

用法：
    python testdata/tools/check_corpus.py                # 只检查
    python testdata/tools/check_corpus.py --fix          # 顺带把 Content-Length 改对
    python testdata/tools/check_corpus.py -v             # 打印每条命中的规则与分数
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_rules as cr  # noqa: E402

THRESHOLD = 5  # engine.inbound_anomaly_threshold

# 每个语料的期望裁决。block = 总分达阈值；challenge = 命中 scanner 类低分规则
# （DESIGN.md §10.2：扫描器类在 block 模式下走挑战而不是直接拦）；
# allow = 必须零命中。
MANIFEST = {
    # ── 必须拦 ──────────────────────────────────────────────────────
    "sqli-union-query.http": "block",
    "sqli-union-post.http": "block",
    "sqli-boolean-json.http": "block",
    "sqli-time-blind.http": "block",
    "xss-event-get.http": "block",
    "xss-script-json.http": "block",
    "xss-entity-encoded.http": "block",
    "rce-cmdi-get.http": "block",
    "rce-log4j-header.http": "block",
    "rce-ssti-json.http": "block",
    "rce-xxe-body.http": "block",
    "lfi-traversal-get.http": "block",
    "lfi-encoded-get.http": "block",
    "lfi-php-wrapper.http": "block",
    "rfi-ssrf-metadata.http": "block",
    "upload-webshell-magic.http": "block",
    "upload-double-extension.http": "block",
    "upload-filename-traversal.http": "block",
    "webshell-access.http": "block",
    "webshell-put-body.http": "block",
    "scanner-git-config.http": "block",
    "protocol-cl-te.http": "block",
    "protocol-crlf-param.http": "block",
    "protocol-crlf-body.http": "block",
    # ── 扫描器 UA：只给 2 分，走挑战 ────────────────────────────────
    "scanner-sqlmap-ua.http": "challenge",
    # ── 必须放行 ────────────────────────────────────────────────────
    "normal-search-get.http": "allow",
    "normal-apostrophe-text.http": "allow",
    "normal-rich-text-json.http": "allow",
    "normal-json-api.http": "allow",
    "normal-base64-image.http": "allow",
    "normal-xml-soap.http": "allow",
    "normal-upload-pdf.http": "allow",
    "normal-template-text.http": "allow",
    "normal-api-orders.http": "allow",
    "normal-union-english.http": "allow",
    "normal-select-word.http": "allow",
    "normal-acme-challenge.http": "allow",
    "normal-download-pdf.http": "allow",
    "normal-backup-page.http": "allow",
    "normal-static-asset.http": "allow",
    "normal-checkout-form.http": "allow",
    "normal-search-words.http": "allow",
}


# ── 原始报文解析 ────────────────────────────────────────────────────────
def split_message(raw):
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw:
            head, body = raw.split(sep, 1)
            return head, body
    return raw, ""


def fix_content_length(raw):
    head, body = split_message(raw)
    lines = head.replace("\r\n", "\n").split("\n")
    out = [lines[0]]
    seen = False
    for line in lines[1:]:
        if line.lower().startswith("content-length:"):
            out.append("Content-Length: %d" % len(body.encode("utf-8")))
            seen = True
        else:
            out.append(line)
    if not seen and ("\n\n" in raw or "\r\n\r\n" in raw):
        out.append("Content-Length: %d" % len(body.encode("utf-8")))
    return "\n".join(out) + "\n\n" + body


def parse_params(s):
    """query / form-urlencoded：保留重复键，值不做 URL 解码（引擎里由变换链负责）。"""
    params = {}
    if not s:
        return params
    for chunk in s.split("&"):
        if not chunk:
            continue
        if "=" in chunk:
            k, v = chunk.split("=", 1)
        else:
            k, v = chunk, ""
        params.setdefault(k, []).append(v)
    return params


def walk_json(node, prefix, out):
    if isinstance(node, dict):
        for k, v in node.items():
            walk_json(v, "%s.%s" % (prefix, k) if prefix else k, out)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk_json(v, "%s[%d]" % (prefix, i), out)
    else:
        if isinstance(node, bool):
            val = "true" if node else "false"
        elif node is None:
            val = ""
        else:
            val = str(node)
        out.setdefault(prefix, []).append(val)


def parse_multipart(body, boundary):
    """返回 (普通字段 dict, 文件列表)。文件项含 field/filename/magic。"""
    fields, files = {}, []
    delim = "--" + boundary
    parts = body.split(delim)
    for part in parts[1:]:
        if part.startswith("--"):
            break  # 结束标记
        part = part.lstrip("\r\n")
        if "\r\n\r\n" in part:
            phead, pbody = part.split("\r\n\r\n", 1)
        elif "\n\n" in part:
            phead, pbody = part.split("\n\n", 1)
        else:
            continue
        pbody = pbody.rstrip("\r\n")
        name = filename = ""
        for line in phead.replace("\r\n", "\n").split("\n"):
            low = line.lower()
            if low.startswith("content-disposition:"):
                m = re.search(r'name="([^"]*)"', line)
                if m:
                    name = m.group(1)
                m = re.search(r'filename="([^"]*)"', line)
                if m:
                    filename = m.group(1)
        if filename:
            magic = pbody.encode("utf-8", "replace")[:16].hex()
            files.append({"field": name, "filename": filename, "magic": magic,
                          "size": len(pbody.encode("utf-8", "replace")),
                          "body": pbody})
        elif name:
            fields.setdefault(name, []).append(pbody)
    return fields, files


def normalize_path(path, win=True):
    if win:
        path = path.replace("\\", "/")
    path = re.sub(r"/+", "/", path)
    while re.search(r"/\.\.?/", path):
        path = re.sub(r"/\.\.?/", "/", path)
    return path


def build_collections(raw):
    head, body = split_message(raw)
    lines = head.replace("\r\n", "\n").split("\n")
    req_line = lines[0].split(" ")
    method = req_line[0] if req_line else ""
    target = req_line[1] if len(req_line) > 1 else ""
    protocol = req_line[2] if len(req_line) > 2 else ""

    headers = {}
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers.setdefault(k.strip().lower(), []).append(v.strip())

    path, _, query = target.partition("?")
    args_get = parse_params(query)

    ctype_raw = headers.get("content-type", [""])[0] or ""
    ctype = ctype_raw.lower()
    args_post, args_json, args_xml, files = {}, {}, {}, []

    if "application/x-www-form-urlencoded" in ctype:
        args_post = parse_params(body)
    elif "multipart/form-data" in ctype:
        # boundary 是大小写敏感的，必须从原始头里取，不能用 lower() 过的副本
        m = re.search(r"boundary=([^;]+)", ctype_raw, flags=re.IGNORECASE)
        if m:
            args_post, files = parse_multipart(body, m.group(1).strip().strip('"'))
    elif "json" in ctype:
        try:
            walk_json(json.loads(body), "", args_json)
        except ValueError:
            pass
    elif "xml" in ctype:
        for m in re.finditer(r">([^<]+)<", body):
            txt = m.group(1).strip()
            if txt:
                args_xml.setdefault("text", []).append(txt)
        for m in re.finditer(r'\s[a-zA-Z:_.-]+="([^"]*)"', body):
            args_xml.setdefault("attr", []).append(m.group(1))

    args = {}
    for src in (args_get, args_post, args_json, args_xml):
        for k, vs in src.items():
            args.setdefault(k, []).extend(vs)

    cookies = {}
    for cv in headers.get("cookie", []):
        for chunk in cv.split(";"):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                cookies.setdefault(k.strip(), []).append(v.strip())

    colls = {
        "ARGS": args,
        "ARGS_GET": args_get,
        "ARGS_POST": args_post,
        "ARGS_JSON": args_json,
        "ARGS_XML": args_xml,
        "ARGS_NAMES": {k: [k] for k in args},
        "REQUEST_URI": {"": [target]},
        "REQUEST_PATH": {"": [normalize_path(path)]},
        "REQUEST_METHOD": {"": [method]},
        "REQUEST_PROTOCOL": {"": [protocol]},
        "REQUEST_HEADERS": headers,
        "REQUEST_HEADERS_NAMES": {k: [k] for k in headers},
        "REQUEST_COOKIES": cookies,
        "REQUEST_COOKIES_NAMES": {k: [k] for k in cookies},
        "REQUEST_BODY": {"": [body]},
        "FILES": {f["field"]: [f["filename"]] for f in files},
        "FILES_NAMES": {f["field"]: [f["field"]] for f in files},
        "FILES_SIZES": {f["field"]: [str(f["size"])] for f in files},
        "FILES_MAGIC": {f["field"]: [f["magic"]] for f in files},
        "REMOTE_ADDR": {"": ["203.0.113.7"]},
        "ARGS_COUNT": {"": [str(len(args))]},
        "REQUEST_URI_LENGTH": {"": [str(len(target))]},
        "REQUEST_BODY_LENGTH": {"": [str(len(body.encode("utf-8")))]},
    }
    return colls, files


def expand(colls, target):
    coll = colls.get(target.get("collection"))
    if not coll:
        return []
    sel = target.get("selector")
    if target.get("count"):
        return []
    if sel is None:
        keys = list(coll)
    elif sel.startswith("!"):
        keys = [k for k in coll if k != sel[1:]]
    elif sel.startswith("/") and sel.endswith("/"):
        rx = re.compile(sel[1:-1])
        keys = [k for k in coll if rx.search(k)]
    else:
        keys = [sel] if sel in coll else []
    return [v for k in keys for v in coll[k]]


def load_rules(rules_dir):
    out = []
    for fn in sorted(f for f in os.listdir(rules_dir) if f.endswith(".yaml")):
        import yaml
        with open(os.path.join(rules_dir, fn), "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        for rule in (doc.get("rules") or []):
            if isinstance(rule, dict):
                out.append((fn, rule))
    return out


def evaluate_rule(rule, colls):
    """单条规则对当前请求求值，返回是否命中。语义算子没有 Go 实现，跳过。"""
    op = rule.get("operator") or {}
    if op.get("name") in cr.SEMANTIC_OPERATORS:
        return False
    chain = rule.get("transforms") or []
    for target in (rule.get("targets") or []):
        for value in expand(colls, target):
            if cr.op_match(op, cr.apply_chain(value, chain)):
                return True
    return False


def evaluate(raw, rules):
    """按文件顺序求值，并实现  的 chain：
    带 chain: true 的规则命中后，才评估紧随其后的那一条；否则跳过它。"""
    colls, files = build_collections(raw)
    hits = []
    matched_flags = []
    for i, (fn, rule) in enumerate(rules):
        if i > 0:
            prev_fn, prev_rule = rules[i - 1]
            if prev_fn == fn and prev_rule.get("chain") and not matched_flags[i - 1]:
                matched_flags.append(False)  # 链的前置没命中 → 本条不评估
                continue
        ok = evaluate_rule(rule, colls)
        matched_flags.append(ok)
        if ok:
            target = (rule.get("targets") or [{}])[0]
            hits.append((rule.get("id"), rule.get("score") or 0,
                         rule.get("category"), target.get("collection"),
                         target.get("selector")))
    return hits, colls, files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=os.path.join(HERE, "..", "..", "rules"))
    ap.add_argument("--corpus", default=os.path.join(HERE, "..", "corpus"))
    ap.add_argument("--fix", action="store_true", help="重算并写回 Content-Length")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    rules_dir = os.path.abspath(args.rules)
    corpus_dir = os.path.abspath(args.corpus)
    rules = load_rules(rules_dir)
    print("加载规则 %d 条，语料目录 %s" % (len(rules), corpus_dir))

    problems = []
    missing_manifest = []
    for expect_dir, default_verdict in (("positive", "block"), ("negative", "allow")):
        d = os.path.join(corpus_dir, expect_dir)
        if not os.path.isdir(d):
            problems.append("缺少目录 %s" % d)
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".http"):
                continue
            path = os.path.join(d, fn)
            raw = open(path, "r", encoding="utf-8").read()
            if args.fix:
                fixed = fix_content_length(raw)
                if fixed != raw:
                    open(path, "w", encoding="utf-8", newline="\n").write(fixed)
                    raw = fixed
            hits, colls, files = evaluate(raw, rules)
            score = sum(h[1] for h in hits)
            want = MANIFEST.get(fn)
            if want is None:
                missing_manifest.append("%s/%s" % (expect_dir, fn))
                want = default_verdict
            if want == "block":
                ok = score >= THRESHOLD
            elif want == "challenge":
                ok = any(h[2] == "scanner" for h in hits)
            else:
                ok = score == 0
            flag = "OK " if ok else "BAD"
            print("  [%s] %-8s %-34s score=%-3d %s"
                  % (flag, expect_dir, fn, score,
                     ",".join(h[0] for h in hits) if args.verbose or not ok else ""))
            if not ok:
                if want == "block":
                    problems.append("%s/%s 期望 block（阈值 %d），实际 score=%d 命中=%s"
                                    % (expect_dir, fn, THRESHOLD, score,
                                       [h[0] for h in hits]))
                elif want == "challenge":
                    problems.append("%s/%s 期望 scanner 类挑战，实际 score=%d 命中=%s"
                                    % (expect_dir, fn, score, [h[0] for h in hits]))
                else:
                    problems.append("%s/%s 期望零命中，实际 score=%d 命中=%s"
                                    % (expect_dir, fn, score, [h[0] for h in hits]))

    if missing_manifest:
        for m in missing_manifest:
            problems.append("MANIFEST 里没有 %s（已按目录默认值判定，请补上期望）" % m)

    print("-" * 72)
    if problems:
        print("问题 %d 处：" % len(problems))
        for p in problems:
            print("  X %s" % p)
    else:
        print("语料回归：正样本全部达阈值，负样本零命中")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

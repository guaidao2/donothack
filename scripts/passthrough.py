#!/usr/bin/env python3
"""透传保真度检查：同一批请求分别打"直连上游"与"经过 donothack"，逐项比对。

用途：WAF 是透明代理，**任何**对上游语义的改动都是 bug —— 路径被重新编码、
Content-Length 变了、响应头丢了一个、状态码被改写。这个脚本把这类回归变成
一次可重复的检查，P1 加解析层、P2 加检测之后每次都要跑。

比对项：状态码、响应体长度、响应体哈希、Content-Type，以及关心的响应头。

用法：
    python scripts/passthrough.py --direct http://127.0.0.1:8787 --waf http://127.0.0.1:18080
    python scripts/passthrough.py --direct ... --waf ... --paths /,/a?x=1 --post /
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import sys
import urllib.error
import urllib.parse
import urllib.request

# 默认只放**正常业务路径**。
#
# 这里刻意不放攻击 payload：带上 /etc/passwd 这类串的路径会被 WAF 正确拦掉，
# 于是脚本会报"不一致" —— 那不是在测透传，是在测检测（而且还测对了）。
# 攻击样本的验收归 scripts/acceptance.py 管，两边职责别混。
# 想在透传里加自己的路径，用 --paths 传。
DEFAULT_PATHS = [
    "/",
    "/robots.txt",
    "/static/favicon.ico",
    "/this-path-should-not-exist-9f3c",
    "/index.php?id=1",
    "/?q=shoes&page=2&sort=price",
]

# 这些响应头天然会变，不能参与比对
VOLATILE_HEADERS = {"date", "x-request-id", "set-cookie", "expires", "age", "etag:keep"}


def normalize_base(base: str) -> str:
    """把 `host:port` 补成 `http://host:port`。

    为什么要容错：少写 scheme 时 urllib 会抛 "unknown url type"，
    而脚本会把**每一条**都判成"不一致" —— 满屏红色差异看起来像 WAF 篡改了响应，
    实际上是调用方式错了。这种误导比直接报错贵得多。
    """
    base = (base or "").strip()
    if not base:
        raise SystemExit("基址不能为空")
    if "://" not in base:
        base = "http://" + base
    return base.rstrip("/")


def fetch(base: str, path: str, method: str, body: bytes | None, headers: dict) -> dict:
    url = base.rstrip("/") + path
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = resp.read()
            return {
                "status": resp.status,
                "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest()[:16],
                "content_type": resp.headers.get("Content-Type", ""),
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": data,
                "error": None,
            }
    except urllib.error.HTTPError as e:
        data = e.read()
        return {
            "status": e.code,
            "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest()[:16],
            "content_type": e.headers.get("Content-Type", "") if e.headers else "",
            "headers": {k.lower(): v for k, v in (e.headers or {}).items()},
            "body": data,
            "error": None,
        }
    except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
        return {"status": 0, "length": 0, "sha256": "", "content_type": "",
                "headers": {}, "body": b"", "error": str(e)}


def main() -> int:
    parser = argparse.ArgumentParser(description="透传保真度检查")
    parser.add_argument("--direct", required=True, help="直连上游的基址（可写 host:port，自动补 http://）")
    parser.add_argument("--waf", required=True, help="经过 donothack 的基址（可写 host:port，自动补 http://）")
    parser.add_argument("--paths", default="", help="逗号分隔的路径列表")
    parser.add_argument("--post", default="", help="额外对这些路径发一次 POST（表单）")
    parser.add_argument("--method", default="GET")
    args = parser.parse_args()

    paths = [p for p in args.paths.split(",") if p] if args.paths else list(DEFAULT_PATHS)

    cases: list[tuple[str, str, bytes | None, dict]] = [
        (args.method, p, None, {"User-Agent": "passthrough-check/1.0"}) for p in paths
    ]
    for p in [x for x in args.post.split(",") if x]:
        cases.append(("POST", p, b"user=admin&pass=1",
                      {"User-Agent": "passthrough-check/1.0",
                       "Content-Type": "application/x-www-form-urlencoded"}))

    failures: list[str] = []
    print(f"{'方法':<6}{'路径':<40}{'直连':>18}{'经WAF':>18}  结论")
    print("-" * 96)

    direct_base = normalize_base(args.direct)
    waf_base = normalize_base(args.waf)

    for method, path, body, headers in cases:
        d = fetch(direct_base, path, method, body, headers)
        w = fetch(waf_base, path, method, body, headers)

        same_status = d["status"] == w["status"]
        same_len = d["length"] == w["length"]
        same_hash = d["sha256"] == w["sha256"]
        same_ct = d["content_type"] == w["content_type"]

        # 响应头逐项比对（忽略易变头）
        hdr_diffs = []
        for key, val in d["headers"].items():
            if key in VOLATILE_HEADERS:
                continue
            if w["headers"].get(key) != val:
                hdr_diffs.append(f"{key}: {val!r} -> {w['headers'].get(key)!r}")

        ok = same_status and same_len and same_hash and same_ct and not hdr_diffs and not d["error"] and not w["error"]
        verdict = "一致" if ok else "**不一致**"

        left = f"{d['status']} {d['length']}B"
        right = f"{w['status']} {w['length']}B"
        print(f"{method:<6}{path:<40}{left:>18}{right:>18}  {verdict}")

        if not ok:
            if d["error"] or w["error"]:
                failures.append(f"{method} {path}: 直连错误={d['error']} WAF错误={w['error']}")
            if not same_status:
                failures.append(f"{method} {path}: 状态码 {d['status']} -> {w['status']}")
            if not same_len:
                failures.append(f"{method} {path}: 长度 {d['length']} -> {w['length']}")
            if not same_hash:
                failures.append(f"{method} {path}: 响应体哈希不同 {d['sha256']} -> {w['sha256']}")
            if not same_ct:
                failures.append(f"{method} {path}: Content-Type {d['content_type']!r} -> {w['content_type']!r}")
            for h in hdr_diffs:
                failures.append(f"{method} {path}: 响应头 {h}")

    print()
    if failures:
        print(f"发现 {len(failures)} 处不一致：")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"全部一致（{len(cases)} 个请求）—— 代理没有改动上游语义")
    return 0


if __name__ == "__main__":
    sys.exit(main())

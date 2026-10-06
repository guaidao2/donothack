#!/usr/bin/env python3
"""主动类快速验收：只跑代表性端点的定向检测，不爬全站。

为什么要这个脚本：
  `crackweb crawl --depth 2` 一次要十几分钟，而且**抓不到编码型绕过** ——
  它对发现到的参数用固定 payload 集，不做结构推导与编码代数升级。
  真正能打到 `base64(JSON)`、JSON 字段级注入的是 `crackweb scan -u <url>`（定向模式），
  单个端点约 8 秒。日常改完代码要的是"主动注入类归零"这个结论，
  那就只跑定向模式在这几个代表性端点上，几十秒出结果。

判据：
  1. 每个端点跑一次定向扫描；
  2. 汇总所有 `tags` 含 `injection` 的 finding —— **必须为 0**；
  3. 非注入类（`exposed-path` / `passive-*`）只记录，不作为失败依据
     （那些是应用侧与传输层的事，见 docs/ACCEPTANCE.md）。

用法：
    python scripts/active_check.py                      # 用默认端点表
    python scripts/active_check.py --base http://127.0.0.1:18080
    python scripts/active_check.py --endpoint "/user/id-b64-json?id=eyJ1aWQiOjEsIm1sIjoiMSJ9"
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ".exe" if os.name == "nt" else ""
CRACKWEB = ROOT / ".tmp" / "crackweb" / "crackweb_1.6.4_windows_amd64" / f"crackweb{EXE}"
OUTDIR = ROOT / ".tmp" / "p6" / "active"

# 代表性端点：覆盖本项目规则集的几条主线。
# 每条都写明"打什么"——端点表本身就是验收范围的一部分，不能是一串无注释的 URL。
DEFAULT_ENDPOINTS: list[tuple[str, str]] = [
    ("/user/id-b64-json?id=eyJ1aWQiOjEsIm1sIjoiMSJ9", "base64(JSON) 参数文档（编码型绕过那条线）"),
    ("/expr/injection?a=1", "SSTI 模板求值"),
    ("/bruteplayground/by-order-id?orderId=1", "反射型 XSS"),
    ("/download?file=readme.txt", "路径穿越 / LFI"),
    ("/product/list?category=books&id=1", "SQL 注入（普通参数）"),
    ("/?q=shoes", "普通业务参数（对照：不该报任何东西）"),
]

INJECTION_TAGS = {"injection"}


def run_scan(base: str, endpoint: str, tag: str, timeout: int = 180) -> dict | None:
    OUTDIR.mkdir(parents=True, exist_ok=True)
    out = OUTDIR / f"scan-{tag}.json"
    cmd = [str(CRACKWEB), "--lang", "zh", "scan", "-u", base.rstrip("/") + endpoint, "-o", str(out)]
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"    [超时] 超过 {timeout}s 未完成")
        return None
    if not out.exists():
        print(f"    [失败] 没有产出报告（退出码 {proc.returncode}）")
        if proc.stderr:
            print("      " + proc.stderr.strip().splitlines()[-1][:160])
        return None
    try:
        return json.loads(out.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"    [失败] 报告不是合法 JSON：{e}")
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="主动类快速验收（定向模式，不爬全站）")
    ap.add_argument("--base", default="http://127.0.0.1:18080", help="经过 WAF 的基址")
    ap.add_argument("--endpoint", action="append", default=[], help="自定义端点（可重复）")
    ap.add_argument("--timeout", type=int, default=180, help="单个端点超时（秒）")
    args = ap.parse_args()

    if not CRACKWEB.exists():
        print(f"找不到扫描器：{CRACKWEB}", file=sys.stderr)
        print("（crackweb 放在 .tmp/crackweb/ 下，.tmp 不进 git）", file=sys.stderr)
        return 2

    endpoints = DEFAULT_ENDPOINTS
    if args.endpoint:
        endpoints = [(e, "自定义") for e in args.endpoint]

    print(f"目标 {args.base}    端点 {len(endpoints)} 个    （定向模式，非全站爬取）\n")

    all_injections: list[tuple[str, dict]] = []
    rows: list[tuple[str, str, int, int, float]] = []
    total_requests = 0

    for endpoint, purpose in endpoints:
        tag = endpoint.strip("/").replace("/", "-").replace("?", "_").replace("=", "")[:40] or "root"
        print(f"  → {endpoint}\n      {purpose}")
        t0 = time.time()
        rep = run_scan(args.base, endpoint, tag, args.timeout)
        dt = time.time() - t0
        if rep is None:
            return 3
        findings = rep.get("findings", [])
        injections = [f for f in findings if INJECTION_TAGS & set(f.get("tags") or [])]
        all_injections.extend((endpoint, f) for f in injections)
        reqs = rep.get("requests", 0)
        total_requests += reqs
        rows.append((endpoint, purpose, len(findings), len(injections), dt))
        print(f"      {reqs} 请求 / {dt:.1f}s → findings {len(findings)}，其中注入类 {len(injections)}")
        for f in findings:
            mark = "注入!" if INJECTION_TAGS & set(f.get("tags") or []) else "     "
            print(f"        [{mark}] {f.get('severity','?'):<8} {f.get('check','?'):<24} {f.get('parameter') or ''}")

    print("\n" + "=" * 72)
    print(f"{'端点':<44}{'findings':>10}{'注入类':>8}")
    print("-" * 72)
    for endpoint, _purpose, n, inj, _dt in rows:
        print(f"{endpoint[:42]:<44}{n:>10}{inj:>8}")
    print("-" * 72)
    print(f"共 {total_requests} 个请求，用时 {sum(r[4] for r in rows):.1f}s")

    if all_injections:
        print(f"\n主动注入类 finding：{len(all_injections)} 条 —— **未归零**")
        for endpoint, f in all_injections:
            print(f"  [{f.get('severity')}] {f.get('check')} @ {endpoint}")
            print(f"      参数 {f.get('parameter')}  payload {f.get('payload')!r}")
        return 1

    print("\n主动注入类 finding：0 —— 通过（非注入类见各端点明细，属应用/传输层）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

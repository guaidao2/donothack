#!/usr/bin/env python3
"""donothack 端到端压测：分别压"直连上游"与"经过 donothack"，输出对比表与报告。

流程与 docs/PERFORMANCE.md §10.2 一致：
  1. 编译 donothack / loadgen / testupstream 到 dist/
  2. 起假上游 testupstream
  3. 压直连上游（基线）
  4. 起 donothack（指定档位）
  5. 压经过 donothack
  6. 采集 RPS、P50/P90/P99、donothack 的 RSS
  7. 输出对比表，报告写入 docs/bench/

注意：本机跑出来的数字**不能**当作真机基线。模拟不出真实 VPS 的 CPU 型号、
磁盘 IO 与网络栈 —— 那必须在一台真机（目标档 2 vCPU / 2 GiB）上跑一次。

用法：
    python scripts/bench.py --profile medium --duration 15s --concurrency 64
    python scripts/bench.py --profile small --gomaxprocs 1 --gomemlimit 48MiB
    python scripts/bench.py --upstream http://127.0.0.1:8787   # 拿真实站点当上游
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IS_WINDOWS = os.name == "nt"
EXE = ".exe" if IS_WINDOWS else ""

# 目标档的验收线（docs/PERFORMANCE.md §2.1）
TARGETS = {
    "small": {"rps": 3000, "rss_mib": 48.0, "overhead_pct": 10.0},
    "medium": {"rps": 8000, "rss_mib": 120.0, "overhead_pct": 10.0},
    "large": {"rps": 20000, "rss_mib": 600.0, "overhead_pct": 10.0},
}


def log(msg: str) -> None:
    print(msg, flush=True)


def section(msg: str) -> None:
    print(f"\n=== {msg} ===", flush=True)


def write_text(path: Path, text: str) -> None:
    """按 UTF-8 无 BOM 写文件（Windows 上默认编码与 BOM 都会惹麻烦）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def build(dist: Path) -> None:
    section("编译")
    env = dict(os.environ, CGO_ENABLED="0", GOAMD64="v1")
    for pkg, name in [
        ("./cmd/donothack", f"donothack{EXE}"),
        ("./cmd/loadgen", f"loadgen{EXE}"),
        ("./cmd/testupstream", f"testupstream{EXE}"),
        ("./cmd/plainproxy", f"plainproxy{EXE}"),
    ]:
        proc = subprocess.run(
            ["go", "build", "-trimpath", "-o", str(dist / name), pkg],
            cwd=ROOT,
            env=env,
        )
        if proc.returncode != 0:
            raise SystemExit(f"编译 {pkg} 失败")


def rss_mib(pid: int) -> float:
    """读进程常驻内存。

    刻意不引 psutil：这个脚本要能在只有标准库的机器上跑。
    """
    if IS_WINDOWS:
        proc = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        # 形如 "donothack.exe","1234","Console","1","12,345 K"
        m = re.findall(r'"([\d,]+)\s*K"', proc.stdout or "")
        if m:
            return int(m[-1].replace(",", "")) / 1024.0
        return 0.0
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024.0
    except OSError:
        pass
    return 0.0


def parse_loadgen(output: str | None) -> dict[str, float]:
    output = output or ""
    """把 loadgen 的文本输出解析成数字。字段名随输出语言变化，因此按冒号取值。"""
    def value(prefix: str) -> str:
        for line in output.splitlines():
            if line.strip().startswith(prefix):
                return line.split(":", 1)[1].strip()
        return ""

    def num(text: str) -> float:
        m = re.search(r"([\d.]+)", text)
        return float(m.group(1)) if m else 0.0

    def ms(text: str) -> float:
        m = re.search(r"([\d.]+)\s*(µs|us|ms|s)", text)
        if not m:
            return 0.0
        v = float(m.group(1))
        unit = m.group(2)
        if unit in ("µs", "us"):
            return v / 1000.0
        if unit == "s":
            return v * 1000.0
        return v

    return {
        "requests": num(value("总请求")),
        "ok": num(value("成功 2xx")),
        "non2xx": num(value("非 2xx")),
        "errors": num(value("错误")),
        "rps": num(value("RPS")),
        "p50": ms(value("延迟 p50")),
        "p90": ms(value("延迟 p90")),
        "p99": ms(value("延迟 p99")),
        "max": ms(value("延迟 max")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="donothack 端到端压测")
    parser.add_argument("--profile", default="medium", choices=["small", "medium", "large"])
    parser.add_argument("--duration", default="15s")
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--body-size", type=int, default=0)
    parser.add_argument("--upstream-port", type=int, default=19000)
    parser.add_argument("--waf-port", type=int, default=18080)
    parser.add_argument("--plain-port", type=int, default=18081)
    parser.add_argument("--upstream", default="", help="直接用外部上游（如靶场），跳过 testupstream")
    parser.add_argument("--gomaxprocs", type=int, default=0)
    parser.add_argument("--gomemlimit", default="")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--label", default="")
    args = parser.parse_args()

    dist = ROOT / "dist"
    tmp = ROOT / ".tmp" / "bench"
    bench_docs = ROOT / "docs" / "bench"
    for d in (dist, tmp, bench_docs):
        d.mkdir(parents=True, exist_ok=True)

    if not args.skip_build:
        build(dist)

    child_env = dict(os.environ)
    if args.gomaxprocs > 0:
        child_env["GOMAXPROCS"] = str(args.gomaxprocs)
    if args.gomemlimit:
        child_env["GOMEMLIMIT"] = args.gomemlimit

    upstream_url = args.upstream or f"http://127.0.0.1:{args.upstream_port}"
    cfg_path = tmp / f"config-{args.profile}.yaml"
    write_text(
        cfg_path,
        f"""profile: {args.profile}
listen:
  addr: "127.0.0.1:{args.waf_port}"
upstream:
  url: "{upstream_url}"
log:
  level: warn
  output: file
  file: "./.tmp/bench/waf-{args.profile}.jsonl"
  app_output: file
  app_file: "./.tmp/bench/waf-app-{args.profile}.log"
engine:
  mode: detect
""",
    )

    procs: list[subprocess.Popen] = []

    def stop_all() -> None:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()

    try:
        # 假上游（用外部上游时跳过）
        if not args.upstream:
            section(f"启动假上游 :{args.upstream_port}")
            procs.append(
                subprocess.Popen(
                    [
                        str(dist / f"testupstream{EXE}"),
                        "-addr", f"127.0.0.1:{args.upstream_port}",
                        "-size", "1024",
                    ],
                    cwd=ROOT,
                    env=child_env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
            time.sleep(0.8)

        loadgen = str(dist / f"loadgen{EXE}")
        common = [
            "-c", str(args.concurrency),
            "-d", args.duration,
            "-bodysize", str(args.body_size),
        ]

        section("压直连上游（参考值，不是公平基线）")
        base_proc = subprocess.run(
            [loadgen, "-label", "baseline-direct", "-url", upstream_url + "/"] + common,
            cwd=ROOT, env=child_env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        base = parse_loadgen(base_proc.stdout)
        print(base_proc.stdout.strip())

        # 公平基线：同样的反向代理、同样的 Transport 调优，但不做任何检测。
        # 直连是一跳、WAF 是两跳，拿直连当基线量的是"多了一跳"，不是"WAF 慢"。
        section(f"启动裸反向代理 :{args.plain_port}（公平基线）")
        plain = subprocess.Popen(
            [str(dist / f"plainproxy{EXE}"),
             "-addr", f"127.0.0.1:{args.plain_port}",
             "-upstream", upstream_url],
            cwd=ROOT, env=child_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        procs.append(plain)
        time.sleep(1.2)

        section("压裸反向代理（公平基线）")
        plain_proc = subprocess.run(
            [loadgen, "-label", "baseline-plainproxy",
             "-url", f"http://127.0.0.1:{args.plain_port}/"] + common,
            cwd=ROOT, env=child_env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        plain_stats = parse_loadgen(plain_proc.stdout)
        print(plain_proc.stdout.strip())

        plain.terminate()
        try:
            plain.wait(timeout=5)
        except subprocess.TimeoutExpired:
            plain.kill()

        section(f"启动 donothack :{args.waf_port}（profile={args.profile}）")
        waf = subprocess.Popen(
            [str(dist / f"donothack{EXE}"), "-c", str(cfg_path.relative_to(ROOT))],
            cwd=ROOT, env=child_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        procs.append(waf)
        time.sleep(1.5)

        section("压经过 donothack")
        waf_proc = subprocess.run(
            [loadgen, "-label", "through-waf",
             "-url", f"http://127.0.0.1:{args.waf_port}/"] + common,
            cwd=ROOT, env=child_env, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        through = parse_loadgen(waf_proc.stdout)
        print(waf_proc.stdout.strip())

        mem = rss_mib(waf.pid) if waf.poll() is None else 0.0

        # ---- 对比 ----
        # 关键数字是 donothack 相对"裸代理"的开销；相对直连的差值只作参考。
        overhead = (1 - through["rps"] / plain_stats["rps"]) * 100 if plain_stats["rps"] else 0.0
        drop_vs_direct = (1 - through["rps"] / base["rps"]) * 100 if base["rps"] else 0.0

        section("对比")
        rows = [
            ("RPS", f"{base['rps']:.0f}", f"{plain_stats['rps']:.0f}", f"{through['rps']:.0f}",
             f"{overhead:+.1f}%"),
            ("P50 (ms)", f"{base['p50']:.3f}", f"{plain_stats['p50']:.3f}", f"{through['p50']:.3f}",
             f"{through['p50'] - plain_stats['p50']:+.3f}"),
            ("P90 (ms)", f"{base['p90']:.3f}", f"{plain_stats['p90']:.3f}", f"{through['p90']:.3f}",
             f"{through['p90'] - plain_stats['p90']:+.3f}"),
            ("P99 (ms)", f"{base['p99']:.3f}", f"{plain_stats['p99']:.3f}", f"{through['p99']:.3f}",
             f"{through['p99'] - plain_stats['p99']:+.3f}"),
            ("错误数", f"{base['errors']:.0f}", f"{plain_stats['errors']:.0f}", f"{through['errors']:.0f}", ""),
            ("非 2xx", f"{base['non2xx']:.0f}", f"{plain_stats['non2xx']:.0f}", f"{through['non2xx']:.0f}", ""),
        ]
        width = max(len(r[0]) for r in rows) + 2
        print(f"{'指标'.ljust(width)}{'直连'.rjust(11)}{'裸代理'.rjust(11)}{'donothack'.rjust(11)}{'WAF开销'.rjust(11)}")
        for name, b, p, w, d in rows:
            print(f"{name.ljust(width)}{b.rjust(11)}{p.rjust(11)}{w.rjust(11)}{d.rjust(11)}")
        print(f"\ndonothack RSS: {mem:.1f} MiB")
        print(f"相对直连的吞吐降幅（参考值，含两跳成本）: {drop_vs_direct:.1f}%")

        target = TARGETS[args.profile]
        verdict_rps = "达标" if through["rps"] >= target["rps"] else "未达标"
        verdict_rss = "达标" if mem <= target["rss_mib"] else "未达标"
        verdict_overhead = "达标" if overhead <= target["overhead_pct"] else "未达标"
        print(f"吞吐目标 ≥ {target['rps']} rps：{verdict_rps}")
        print(f"相对裸代理的吞吐降幅 < {target['overhead_pct']}%：{verdict_overhead}（实测 {overhead:.1f}%）")
        print(f"内存目标 ≤ {target['rss_mib']} MiB：{verdict_rss}")

        # ---- 报告 ----
        stamp = time.strftime("%Y%m%d-%H%M%S")
        tag = args.label or subprocess.run(
            ["git", "describe", "--tags", "--always", "--dirty"],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        ).stdout.strip() or "unknown"
        report = bench_docs / f"{stamp}-{args.profile}.md"

        def block(title: str, text: str) -> str:
            return f"## {title}\n\n```\n{text.strip()}\n```\n"

        write_text(
            report,
            "\n".join(
                [
                    f"# 压测报告 {stamp}（profile={args.profile}）",
                    "",
                    "> **本机数字，不是真机基线。** 模拟不出真实 VPS 的 CPU 型号、磁盘 IO 与网络栈。",
                    "> 真机基线必须在一台目标档 VPS 上跑一次才作数（docs/PERFORMANCE.md §10.3）。",
                    "",
                    "| 项 | 值 |",
                    "| --- | --- |",
                    f"| 版本 | {tag} |",
                    f"| 档位 | {args.profile} |",
                    f"| 上游 | {upstream_url} |",
                    f"| 并发 | {args.concurrency} |",
                    f"| 时长 | {args.duration} |",
                    f"| 请求体 | {args.body_size} 字节 |",
                    f"| GOMAXPROCS | {args.gomaxprocs or '默认'} |",
                    f"| GOMEMLIMIT | {args.gomemlimit or '未设置'} |",
                    f"| 平台 | {platform.platform()} |",
                    f"| donothack RSS | {mem:.1f} MiB |",
                    "",
                    "> **公平基线是「裸反向代理」**：同样的 Transport 调优，但不做检测。",
                    "> 直连上游是一跳、经过 WAF 是两跳，拿直连当基线量的是「多了一跳」，不是「WAF 慢」。",
                    "> 因此看开销请看最后一列（donothack 相对裸代理）。",
                    "",
                    "| 指标 | 直连 | 裸代理 | donothack | WAF 开销 |",
                    "| --- | --- | --- | --- | --- |",
                ]
                + [f"| {n} | {b} | {p} | {w} | {d} |" for n, b, p, w, d in rows]
                + [
                    "",
                    f"- 吞吐目标 ≥ {target['rps']} rps：**{verdict_rps}**",
                    f"- 相对裸代理吞吐降幅 < {target['overhead_pct']}%：**{verdict_overhead}**（实测 {overhead:.1f}%）",
                    f"- 内存目标 ≤ {target['rss_mib']} MiB：**{verdict_rss}**",
                    f"- 相对直连的吞吐降幅（仅参考，含两跳成本）：{drop_vs_direct:.1f}%",
                    "",
                    block("直连上游（参考）", base_proc.stdout),
                    block("裸反向代理（公平基线）", plain_proc.stdout),
                    block("经过 donothack", waf_proc.stdout),
                ]
            )
            + "\n",
        )
        print(f"\n报告已写入: {report.relative_to(ROOT)}")
        return 0
    finally:
        stop_all()


if __name__ == "__main__":
    sys.exit(main())

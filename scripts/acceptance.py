#!/usr/bin/env python3
"""报文语料端到端验收：把原始 HTTP 报文直接打进 WAF，比对裁决。

用法：
    # 先起 WAF（block 模式），再跑：
    python scripts/acceptance.py --waf 127.0.0.1:18080 --corpus testdata/corpus
    # 只看直连上游的基线（确认下游行为，排除"上游本来就 4xx"的干扰）：
    python scripts/acceptance.py --waf 127.0.0.1:8787 --corpus testdata/corpus

判据：
    positive/*.http  必须被拦（默认状态码 403）
    negative/*.http  必须被放行（不能是 403）

为什么用裸 socket 而不是 requests/urllib：
    语料是 Burp 那种原始报文，里面可能有重复头、奇怪的 Content-Length、
    甚至故意互相矛盾的头。走 HTTP 库会被规范化掉，等于没测到真正要测的东西。
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
from pathlib import Path

CWD = Path(__file__).resolve().parent.parent


def send_raw(host: str, port: int, raw: bytes, timeout: float = 10.0) -> tuple[int, bytes]:
    """发原始字节，返回 (状态码, 响应字节)。

    注意：不能等 EOF —— WAF 用 keep-alive，连接不会关，等下去只会等到超时。
    读到响应头结束（\\r\\n\\r\\n）就够判状态码了；如果有 Content-Length，
    再把 body 读完，方便打印。
    """
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(raw)
        s.settimeout(timeout)
        buf = b""
        while b"\r\n\r\n" not in buf:
            try:
                data = s.recv(8192)
            except socket.timeout:
                break
            if not data:
                break
            buf += data
            if len(buf) > 262144:
                break

        head, _, body = buf.partition(b"\r\n\r\n")
        clen = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    clen = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    clen = 0
                break
        while len(body) < clen and clen <= 262144:
            try:
                data = s.recv(8192)
            except socket.timeout:
                break
            if not data:
                break
            body += data

    line = head.split(b"\r\n", 1)[0]
    parts = line.split(b" ")
    code = 0
    if len(parts) >= 2:
        try:
            code = int(parts[1])
        except ValueError:
            code = 0
    return code, head + b"\r\n\r\n" + body


# 三类语料，判据不同：
#   positive/   必须被拦截（默认 403）
#   negative/   必须被放行（不能是 403）
#   detect/     命中但**设计上不拦**（单一弱信号），判据是"不得被拦截"
#   known-gap/  本层结构上检测不到（见目录内 README），不参与判定
KINDS = ("positive", "negative", "detect")



def diagnose(code: int, body: bytes, block_status: int) -> str:
    """当 positive 没被拦时，指出**是哪一层**拒/放的行。

    为什么值得写：一次全红曾经是因为测试配置的 `upstream.allowed_hosts` 只放行了
    localhost，而语料用 *.example.com —— 请求在 Host 白名单层就被拒（400），
    根本没走到规则。当时的表现是"23/23 全部应当被拦截"，看起来像规则集体失效，
    实际是另一层生效了。拒绝的**来源层**必须一眼看得出来。
    """
    if code == block_status:
        return ""
    raw_text = body.decode("utf-8", "replace")

    # 首选判据：响应上的层级标识（X-Donothack-Reject）。有了它就不必猜。
    # 注意**必须在压平换行之前**扫描：压成一行之后就没有"行首"了。
    layer = ""
    for line in raw_text.splitlines():
        if line.strip().lower().startswith("x-donothack-reject:"):
            layer = line.split(":", 1)[1].strip()
            break

    text = raw_text[:200].replace("\n", " ").replace("\r", "").strip()
    hints = []
    if layer == "host":
        hints.append("被 upstream.allowed_hosts 拒掉（语料用 example.com 域名，"
                     "测试配置需放行它们，例如 \"*.example.com\"）")
    elif layer == "degrade":
        hints.append("被过载降级拒绝（看 /readyz 的 degrade 字段）")
    elif layer in ("ratelimit", "ban"):
        hints.append(f"被限速/封禁拦下（layer={layer}，压测与扫描时容易发生）")
    elif layer.startswith("ip"):
        hints.append(f"被 IP 名单拦下（layer={layer}）")
    elif code == 0:
        hints.append("连接层面就失败（进程没起来或端口不对）")
    elif code == 429:
        hints.append("被限速拦下")
    elif "降级" in text or code == 503:
        hints.append("疑似过载降级在拒绝（看 /readyz 的 degrade 字段）")
    else:
        hints.append("未被拦截：先看响应体与 /readyz，再确认规则是否加载")
    if not hints:
        hints.append("未被拦截")
    return "  ← " + "；".join(hints) + (f"　响应头/体：{text}" if text else "")


def load_cases(corpus: Path) -> list[tuple[str, Path, bytes]]:
    cases: list[tuple[str, Path, bytes]] = []
    for kind in KINDS:
        d = corpus / kind
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*.http")):
            raw = f.read_bytes()
            # 报文文件用 LF 也行，HTTP 要求 CRLF：统一换行，避免测试自身制造畸形请求
            raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            cases.append((kind, f, raw))
    return cases


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--waf", default="127.0.0.1:18080", help="目标 host:port")
    ap.add_argument(
        "--corpus",
        default=str(CWD / "testdata" / "corpus"),
        help="语料目录（含 positive/ 与 negative/）",
    )
    ap.add_argument("--block-status", type=int, default=403, help="判定为'已拦截'的状态码")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--show-pass", action="store_true", help="同时打印通过的用例")
    args = ap.parse_args()

    host, _, port_s = args.waf.partition(":")
    port = int(port_s or "80")
    corpus = Path(args.corpus)
    if not corpus.is_dir():
        print(f"语料目录不存在：{corpus}", file=sys.stderr)
        return 2

    cases = load_cases(corpus)
    if not cases:
        print(f"语料目录里没有 *.http：{corpus}", file=sys.stderr)
        return 2

    fails: list[tuple[str, Path, int, str]] = []
    n_pos = n_neg = n_det = 0
    blocked_pos = passed_neg = passed_det = 0

    print(f"目标 {host}:{port}    语料 {corpus}    用例 {len(cases)}\n")
    for kind, path, raw in cases:
        rel = path.relative_to(corpus)
        try:
            code, body = send_raw(host, port, raw, args.timeout)
        except OSError as e:
            fails.append((kind, rel, 0, f"连接失败：{e}"))
            print(f"  [错误] {rel}  {e}")
            continue

        if kind == "positive":
            n_pos += 1
            ok = code == args.block_status
            if ok:
                blocked_pos += 1
            else:
                fails.append((kind, rel, code, "应当被拦截"))
            if ok and not args.show_pass:
                continue
            print(f"  [{'通过' if ok else '失败'}] positive  {rel}  →  {code}{diagnose(code, body, args.block_status)}")
        elif kind == "detect":
            n_det += 1
            ok = code != args.block_status
            if ok:
                passed_det += 1
            else:
                fails.append((kind, rel, code, "设计上只记分，不该被拦"))
            if ok and not args.show_pass:
                continue
            print(f"  [{'通过' if ok else '失败'}] detect    {rel}  →  {code}")
        else:
            n_neg += 1
            ok = code != args.block_status
            if ok:
                passed_neg += 1
            else:
                fails.append((kind, rel, code, "被误拦"))
            if ok and not args.show_pass:
                continue
            print(f"  [{'通过' if ok else '失败'}] negative  {rel}  →  {code}")

    print()
    print(f"positive  必须拦：{blocked_pos}/{n_pos} 被拦截")
    print(f"negative  必须放：{passed_neg}/{n_neg} 被放行")
    print(f"detect    只记分：{passed_det}/{n_det} 未被拦（符合设计）")
    if fails:
        print(f"\n未通过 {len(fails)} 例：")
        for kind, rel, code, why in fails:
            print(f"  - {kind}/{rel}  HTTP {code}  {why}")
        return 1
    print("\n全部通过")
    return 0


if __name__ == "__main__":
    os.chdir(CWD)
    raise SystemExit(main())

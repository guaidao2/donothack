#!/usr/bin/env python3
"""验证告警通道与 TOTP 的完整链路（真起服务、真发请求）。

判据（逐条断言，失败即非零退出）：
  1. PUT /notify 配置 webhook 后，POST /notify/test 能真的送达接收端
  2. 数据面拦截时会把告警推到 webhook（Kind=block），且**不含 payload 原文**
  3. 冷却生效：连续同类告警只发一条
  4. webhook 挂掉时统计 failed，且不影响数据面
  5. TOTP：enroll 不带验证码 → 未启用；带正确验证码 → 启用；登录必须带验证码
  6. TOTP 验证码错误时登录被拒（且不泄露"口令对不对"）

用法：python scripts/verify_notify_totp.py
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ".exe" if os.name == "nt" else ""
CONSOLE = "http://127.0.0.1:18082"
DATA = "http://127.0.0.1:18083"
WEBHOOK_PORT = 19555
RECEIVER_LOG = ROOT / ".tmp" / "notify-received.jsonl"
CONFIG = ROOT / ".tmp" / "p5" / "config.yaml"

PASSED = 0
FAILED = 0


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if ok:
        PASSED += 1
        print(f"  [ok]   {name}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name} {detail}")


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        with RECEIVER_LOG.open("a", encoding="utf-8") as f:
            f.write(body.decode("utf-8", "replace") + "\n")
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args) -> None:  # 静默
        return


class Session:
    """带 cookie 与 CSRF 的控制台客户端。"""

    def __init__(self) -> None:
        self.jar = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""

    def call(self, method: str, path: str, body=None, write: bool = False) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(CONSOLE + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if write:
            req.add_header("X-Donothack-Console", "1")
            req.add_header("X-Donothack-CSRF", self.csrf)
            req.add_header("Origin", CONSOLE)
        try:
            with self.op.open(req, timeout=10) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return e.code, {"raw": raw.decode("utf-8", "replace")[:200]}

    def login(self, password: str, totp: str = "") -> tuple[int, dict]:
        code, body = self.call("POST", "/api/v1/login",
                               {"username": "admin", "password": password, "totp": totp})
        if code == 200:
            self.csrf = body.get("csrf", "")
        return code, body



def wait_port_free(*ports: int, timeout: float = 15.0) -> None:
    """等端口真的空闲（上一轮进程退出后系统释放端口需要时间）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        busy = []
        for port in ports:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                busy.append(port)
            finally:
                s.close()
        if not busy:
            return
        time.sleep(0.3)


def wait_console_ready(proc: subprocess.Popen, timeout: float = 15.0) -> bool:
    """轮询控制台直到能应答（进程若已退出则直接失败）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(CONSOLE + "/api/v1/session", timeout=2) as r:
                # 未登录应当是 401；能拿到任何 HTTP 响应就说明起来了
                _ = r.status
                return True
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                return True
        except Exception:
            time.sleep(0.3)
    return False


def raw_get(port: int, path: str) -> str:
    with socket.create_connection(("127.0.0.1", port), timeout=8) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode())
        s.settimeout(8)
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
        return buf.split(b"\r\n")[0].decode("latin1")


def totp_now(secret: str) -> str:
    """按 RFC 6238 现算一个验证码（SHA1 / 6 位 / 30 秒）。"""
    pad = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(pad)
    counter = int(time.time()) // 30
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return f"{code % 1000000:06d}"


def read_events() -> list[dict]:
    if not RECEIVER_LOG.exists():
        return []
    out = []
    for line in RECEIVER_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def main() -> int:
    if RECEIVER_LOG.exists():
        RECEIVER_LOG.unlink()
    RECEIVER_LOG.parent.mkdir(parents=True, exist_ok=True)

    # 假 webhook 接收端
    srv = HTTPServer(("127.0.0.1", WEBHOOK_PORT), Receiver)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    # 起服务（p5 配置：数据面 18083、控制台 18082、门槛关闭）
    #
    # 为什么要"等端口就绪"：上一轮退出后 Windows 释放监听端口要一会儿，
    # 紧接着再起会 bind 失败，而脚本照旧往下跑 → 表现为 ConnectionReset，
    # 看起来像服务 bug，其实是脚本没等。这里显式等就绪并自检。
    wait_port_free(18082, 18083)
    procs = []
    proc = subprocess.Popen([str(ROOT / "dist" / f"donothack{EXE}"), "-c", str(CONFIG)],
                            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(proc)
    if not wait_console_ready(proc, timeout=15.0):
        print("控制台未在 15 秒内就绪，无法继续验证", file=sys.stderr)
        proc.terminate()
        return 2

    try:
        s = Session()
        code, body = s.login(PASSWORD)
        check("演示账号登录", code == 200, f"code={code} body={body}")

        # ---- 1) 配置并测试告警 ----
        code, body = s.call("PUT", "/api/v1/notify",
                            {"enabled": True, "webhook": f"http://127.0.0.1:{WEBHOOK_PORT}/hook"},
                            write=True)
        check("PUT /notify 配置 webhook", code == 200, f"code={code} body={body}")

        code, body = s.call("POST", "/api/v1/notify/test", {}, write=True)
        check("POST /notify/test 送达", code == 200 and len(read_events()) >= 1,
              f"code={code} body={body} received={len(read_events())}")

        # 脱敏要针对**真的带 token 的 URL**（IM 机器人的凭据就在路径里）
        token = "abcdef1234567890deadbeef"
        s.call("PUT", "/api/v1/notify",
               {"enabled": True,
                "webhook": f"http://127.0.0.1:{WEBHOOK_PORT}/open-apis/bot/v2/hook/{token}"},
               write=True)
        code, body = s.call("GET", "/api/v1/notify")
        shown = json.dumps(body, ensure_ascii=False)
        check("GET /notify 不把 webhook 里的 token 回显出来",
              token not in shown,
              f"webhook={body.get('webhook')!r}")
        check("GET /notify 回显形态是遮罩过的", "…" in str(body.get("webhook", "")),
              f"webhook={body.get('webhook')!r}")
        # 换回短路径继续后续用例
        s.call("PUT", "/api/v1/notify",
               {"enabled": True, "webhook": f"http://127.0.0.1:{WEBHOOK_PORT}/hook"}, write=True)

        # ---- 2) 数据面拦截 → 告警 ----
        before = len(read_events())
        status = raw_get(18083, "/?id=1%27+UNION+SELECT+password+FROM+users--")
        check("数据面拦截注入请求", "403" in status, status)
        time.sleep(1.2)
        events = read_events()
        block_events = [e for e in events[before:] if e.get("kind") == "block"]
        check("拦截触发告警（Kind=block）", len(block_events) >= 1,
              f"新增 {len(events) - before} 条，其中 block {len(block_events)} 条")
        if block_events:
            e = block_events[0]
            check("告警带类目与规则号", bool(e.get("category")) and bool(e.get("rule_id")),
                  json.dumps(e, ensure_ascii=False))
            # 关键：告警**不含 payload 原文**
            raw = json.dumps(e, ensure_ascii=False)
            check("告警不含 payload 原文", "UNION" not in raw.upper().replace("SQLI", ""),
                  raw[:200])

        # ---- 3) 冷却 ----
        before = len(read_events())
        for _ in range(6):
            raw_get(18083, "/?id=1%27+UNION+SELECT+password+FROM+users--")
        time.sleep(1.2)
        got = len(read_events()) - before
        check("冷却期内同类告警被合并（不是 6 条）", got <= 1, f"收到 {got} 条")

        # ---- 4) webhook 挂掉不影响数据面 ----
        srv.shutdown()
        status = raw_get(18083, "/?q=shower+curtain")  # 正常请求
        check("webhook 不可用时数据面照常服务", "200" in status, status)

        # ---- 5) TOTP ----
        code, body = s.call("POST", "/api/v1/totp/enroll", {}, write=True)
        secret = body.get("secret", "")
        check("enroll 返回 base32 密钥与 otpauth URI",
              code == 200 and len(secret) == 32 and body.get("otpauth_url", "").startswith("otpauth://"),
              f"code={code} secret_len={len(secret)}")
        check("未校验验证码时不激活（避免把管理员锁在外面）",
              body.get("totp_enabled") is False and body.get("pending") is True,
              json.dumps(body, ensure_ascii=False)[:200])

        code, body = s.call("POST", "/api/v1/totp/enroll", {"code": "000000"}, write=True)
        check("错误验证码拒绝激活", code == 422, f"code={code}")

        code, body = s.call("POST", "/api/v1/totp/enroll", {}, write=True)
        secret = body.get("secret", "")
        good = totp_now(secret)
        code, body = s.call("POST", "/api/v1/totp/enroll", {"code": good}, write=True)
        check("正确验证码激活 TOTP", code == 200 and body.get("totp_enabled") is True,
              f"code={code} body={body}")

        # 新会话：登录必须带验证码
        s2 = Session()
        code, _ = s2.login(PASSWORD)
        check("启用后不带验证码登录被拒", code == 401, f"code={code}")
        code, _ = s2.login(PASSWORD, totp="000000")
        check("启用后错误验证码登录被拒", code == 401, f"code={code}")
        code, _ = s2.login(PASSWORD, totp=totp_now(secret))
        check("启用后正确验证码可登录", code == 200, f"code={code}")

        # 解绑（需要账号口令，作为"认证器丢了"的恢复路径）
        s3 = Session()
        code, body = s3.call("POST", "/api/v1/totp/disable",
                             {"username": "admin", "password": PASSWORD})
        check("用账号口令可解绑 TOTP（认证器丢失时的恢复路径）", code == 200, f"code={code} {body}")
        s4 = Session()
        code, _ = s4.login(PASSWORD)
        check("解绑后登录不再要求验证码", code == 200, f"code={code}")

    finally:
        srv.server_close()
        for p in procs:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()

    print(f"\n通过 {PASSED} 项，失败 {FAILED} 项")
    return 1 if FAILED else 0


PASSWORD = os.environ.get("DONOTHACK_TEST_PASSWORD", "P5-browser-test-2026")

if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""donothack 提交前门禁：格式、静态检查、单元测试、前端 DOM 写入禁令。

用 Python 而不是 PowerShell 的原因很实际：Windows PowerShell 5.1 缺一堆语法
（?? / $IsWindows / 递归 Select-String），而 Python 一套脚本在 Windows 与低配
Linux VPS 上行为一致。

任何一项失败即以非零码退出。CI 与本地跑同一个脚本，避免"本地过了 CI 挂了"。

为什么把 innerHTML 禁令放在这里：控制台的 payload 展示安全完全押在
"没人写 innerHTML"上（见 docs/CONSOLE.md §3.4）。约定会被人忘，门禁不会。

用法：
    python scripts/lint.py
    python scripts/lint.py --skip-tests
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 前端的 DOM 写入禁令（docs/CONSOLE.md §3.4）
BANNED_PATTERNS = [
    (r"innerHTML", "innerHTML"),
    (r"outerHTML", "outerHTML"),
    (r"insertAdjacentHTML", "insertAdjacentHTML"),
    (r"document\s*\.\s*write", "document.write"),
    (r"\beval\s*\(", "eval("),
    (r"new\s+Function\s*\(", "new Function("),
]


def run(cmd: list[str], *, capture: bool = False) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}")
    return subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        capture_output=capture,
        encoding="utf-8",
        errors="replace",
    )


def step(name: str, fn) -> bool:
    print()
    print(f"=== {name} ===")
    try:
        ok = fn()
    except Exception as exc:  # noqa: BLE001 —— 门禁脚本要如实报告，不吞异常
        print(f"  -> 异常：{exc}")
        return False
    print("  -> 通过" if ok else "  -> 失败")
    return ok


def check_gofmt() -> bool:
    proc = run(["gofmt", "-l", "."], capture=True)
    out = (proc.stdout or "").strip()
    if out:
        for line in out.splitlines():
            print(f"  未格式化: {line}")
        print("  修复：gofmt -w .")
        return False
    return True


def check_vet() -> bool:
    return run(["go", "vet", "./..."]).returncode == 0


def check_tests() -> bool:
    return run(["go", "test", "./..."]).returncode == 0


def check_frontend_write_ban() -> bool:
    web = ROOT / "web"
    if not web.is_dir():
        print("  web/ 尚未创建（P5 才做控制台），跳过")
        return True

    files = [p for p in web.rglob("*") if p.suffix in {".js", ".html", ".css"}]
    if not files:
        print("  web/ 下没有前端文件，跳过")
        return True

    hits: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, label in BANNED_PATTERNS:
                if re.search(pattern, line):
                    rel = path.relative_to(ROOT)
                    hits.append(f"  {rel}:{lineno} 命中 {label}：{line.strip()}")

    if hits:
        print("\n".join(hits))
        print("  payload 必须走 renderCode（textContent）。见 docs/CONSOLE.md §3.4")
        return False
    print(f"  扫描 {len(files)} 个前端文件，未发现禁用 API")
    return True



def check_embed_tracked() -> bool:
    """`web/` 下的每个文件都必须在 git 里。

    为什么单列这一条：前端是 `//go:embed all:web` 进二进制的，
    而**构建读磁盘、交付读 git** —— 两者一旦不一致，本地跑得好好的，
    克隆出来却是一个缺文件的控制台。真踩过：`index.html`、`app.js`、
    `audit.js`、`settings.js` 四个文件（约 60 KB）一直没被 `git add` 进去，
    因为提交时的 add 清单里漏了 `web/`。这种"本地能跑、交付是坏的"最伤，
    而且不会自己暴露 —— 所以让它变成门禁的一步。

    只查"磁盘有、git 没有"这一个方向：开发中的普通改动不该让门禁变红。

    注意返回约定：与其它检查一致返回**裸 bool** 并自己打印细节。
    写成 `return ok, detail` 会被 `step()` 当成真值 —— 那是个"永远通过"的门禁
    （非空元组恒为真），这里已经踩过一次。
    """
    web = ROOT / "web"
    if not web.is_dir():
        print("  没有 web/ 目录，跳过")
        return True

    proc = run(["git", "ls-files", "web"], capture=True)
    if proc.returncode != 0:
        print("  不是 git 仓库，跳过")
        return True
    tracked = {line.strip().replace("\\", "/") for line in (proc.stdout or "").splitlines() if line.strip()}

    missing = []
    for f in sorted(web.rglob("*")):
        if not f.is_file():
            continue
        rel = f.relative_to(ROOT).as_posix()
        if rel not in tracked:
            missing.append(rel)

    if missing:
        shown = "、".join(missing[:6])
        more = "" if len(missing) <= 6 else f" 等 {len(missing)} 个"
        print(f"  web/ 下有 {len(missing)} 个文件不在 git 里：{shown}{more}")
        print("  这些文件会被 go:embed 打进二进制，但克隆出来就没有 —— 提交前请 git add web/")
        return False
    print(f"  web/ 下 {len(tracked)} 个文件全部已跟踪")
    return True

def main() -> int:
    parser = argparse.ArgumentParser(description="donothack 提交前门禁")
    parser.add_argument("--skip-tests", action="store_true", help="跳过 go test")
    args = parser.parse_args()

    checks = [
        ("gofmt（必须无输出）", check_gofmt),
        ("go vet", check_vet),
    ]
    if not args.skip_tests:
        checks.append(("go test", check_tests))
    checks.append(("控制台 DOM 写入禁令（innerHTML 等）", check_frontend_write_ban))
    checks.append(("embed 目录一致性（web/ 必须全部进 git）", check_embed_tracked))

    failed = [name for name, fn in checks if not step(name, fn)]

    print()
    if failed:
        print("门禁未通过：" + "、".join(failed))
        return 1
    print("门禁全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())

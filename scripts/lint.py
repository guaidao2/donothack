#!/usr/bin/env python3
"""donothack 提交前门禁：格式、静态检查、单元测试、前端 DOM 写入禁令。

用 Python 而不是 PowerShell 的原因很实际：Windows PowerShell 5.1 缺一堆语法
（?? / $IsWindows / 递归 Select-String），而 Python 一套脚本在 Windows 与低配
Linux VPS 上行为一致。

任何一项失败即以非零码退出。CI 与本地跑同一个脚本，避免"本地过了 CI 挂了"。

为什么把 innerHTML 禁令放在这里：控制台的 payload 展示安全完全押在
"没人写 innerHTML"上。约定会被人忘，门禁不会。

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

# 前端的 DOM 写入禁令
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
    """gofmt 检查**只覆盖源码目录**，不扫 .tmp / dist。

    为什么较真：`.tmp/` 下放的是临时验证程序与联调产物（gitignore），
    给它们套 gofmt 会让门禁因为"别人的草稿没格式化"而红 —— 这次就真踩到了：
    审计员在 `.tmp/audit/` 下留了 9 个一次性程序，门禁直接报未格式化。
    门禁只该对**要交付的东西**说话。
    """
    skip = {".git", ".tmp", "dist", "bin", "node_modules"}
    files: list[str] = []
    for p in sorted(ROOT.rglob("*.go")):
        if any(part in skip for part in p.relative_to(ROOT).parts[:-1]):
            continue
        files.append(p.relative_to(ROOT).as_posix())
    if not files:
        return True
    # **逐文件传参**，不要传 "." —— 传目录会递归进 .tmp，把临时验证程序也算进来。
    proc = run(["gofmt", "-l", *files], capture=True)
    out = (proc.stdout or "").strip()
    if out:
        for line in out.splitlines():
            print(f"  未格式化: {line}")
        print("  修复：gofmt -w <上面的文件>")
        return False
    print(f"  已检查 {len(files)} 个 Go 文件（跳过 .tmp/dist）")
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
        print("  payload 必须走 renderCode（textContent）。见 ")
        return False
    print(f"  扫描 {len(files)} 个前端文件，未发现禁用 API")
    return True



def check_no_emoji() -> bool:
    """禁止在交付物里使用 emoji / 装饰性符号。

    这类符号出现在安全产品的代码、文档与命令输出里显得不专业。
    与前端 DOM 禁令同一个思路 —— 靠"记得别用"是守不住的，得让门禁卡住。

    只扫**交付物**（源码、文档、配置、规则、脚本），跳过 .tmp/dist 这些临时目录。
    CJK、全角标点与排版符号（→ · × µ）不算 emoji，不受影响。
    """
    pattern = re.compile(
        "["
        "\U0001F300-\U0001FAFF"  # emoji 主体
        "\U0001F000-\U0001F2FF"
        "\u2600-\u27BF"          # 杂项符号（对勾、叉、警告、星标都在这里）
        "\u2B00-\u2BFF"
        "\uFE0F"                 # 变体选择符
        "]"
    )
    exts = {".go", ".md", ".yaml", ".yml", ".py", ".js", ".html", ".css", ".json", ".txt", ".http"}
    skip = {".git", ".tmp", "dist", "node_modules"}

    files: list[Path] = []
    if (ROOT / ".git").exists():
        proc = subprocess.run(["git", "ls-files"], cwd=str(ROOT), capture_output=True, text=True)
        files = [ROOT / line for line in (proc.stdout or "").splitlines() if line.strip()]

    hits: list[str] = []
    scanned = 0
    for path in files:
        if path.suffix.lower() not in exts or not path.exists():
            continue
        if any(part in skip for part in path.parts):
            continue
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                try:
                    rel = path.relative_to(ROOT)
                except ValueError:
                    rel = path
                hits.append(f"  {rel}:{lineno}  {line.strip()[:100]}")

    if hits:
        print("\n".join(hits[:20]))
        if len(hits) > 20:
            print(f"  ...还有 {len(hits) - 20} 处")
        print("  请换成朴素说法（表格里用「是 / 否」，正文里直接去掉符号）")
        return False
    print(f"  扫描 {scanned} 个文件，未发现 emoji / 装饰符号")
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


def check_alloc_gate() -> bool:
    """热路径零分配门禁：`BenchmarkEngine_NoMatch` 必须 0 allocs/op。

    为什么要有这一步：这条门禁在  里写了很久，
    但**代码里连基准都不存在** —— 写在文档里的门禁没人跑，等于没有。
    现在它进了 lint，改坏热路径会在提交前就红。

    只跑很短的时间（200ms）够采样即可；门禁看的是 allocs/op，不是吞吐。
    """
    proc = run([
        "go", "test", "./internal/engine/", "-run", "^$",
        "-bench", "^BenchmarkEngine_NoMatch$", "-benchmem", "-benchtime", "200ms",
    ], capture=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode != 0:
        print("  基准没跑起来：")
        for line in out.strip().splitlines()[-6:]:
            print("   ", line)
        return False

    import re

    m = re.search(r"BenchmarkEngine_NoMatch\S*\s+\d+\s+([\d.]+) ns/op\s+([\d.]+) B/op\s+(\d+) allocs/op", out)
    if not m:
        print("  没能从输出里解析出 ns/op 与 allocs/op：")
        for line in out.strip().splitlines()[-6:]:
            print("   ", line)
        return False

    ns, b, allocs = float(m.group(1)), float(m.group(2)), int(m.group(3))
    if allocs != 0:
        print(f"  BenchmarkEngine_NoMatch：{ns:.0f} ns/op、{b:.0f} B/op、**{allocs} allocs/op**")
        print("  门禁要求 0 allocs/op。常见原因：")
        print("   - 变换链里又出现了 make（应写进调用方给的 dst 缓冲）")
        print("   - 新增了按参数名的 string 转换（用 []byte 版本）")
        print("   - 路径走了建字符串那条分支（规范化没改动时应复用 RequestURI 的子串）")
        return False
    if ns > 20000:
        print(f"  BenchmarkEngine_NoMatch 耗时 {ns:.0f} ns/op，超过 20µs 上限")
        return False
    print(f"  BenchmarkEngine_NoMatch：{ns:.0f} ns/op、{b:.0f} B/op、0 allocs/op")
    return True

def check_api_contract() -> bool:
    """控制台前后端参数契约：前端发的查询参数必须有后端读取。

    存在的理由：前端发 `ip=`、后端读 `client_ip` —— 名字不一致又不报错，
    "填了客户端 IP 却返回全部事件"。这类静默忽略靠人点界面查不全，改成门禁。
    """
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "api_contract.py")],
        cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    for line in out.strip().splitlines():
        print("  " + line.rstrip())
    return proc.returncode == 0


def check_filter_inputs_commit_on_input() -> bool:
    """筛选文本框必须在输入时写入筛选状态，不能只等回车。

    存在的理由：筛选框只挂了 onEnter（回车才写状态），而「查询」按钮读的是状态 ——
    「填好条件再点查询」正是最正常的用法，那时状态还是空的，条件被静默丢掉，
    界面照常显示全部结果（看着像没过滤，其实条件根本没发出去）。
    事件页的客户端 IP、审计页的四个、规则页的三个都栽过这一处。
    """
    offenders = []
    for f in sorted((ROOT / "web" / "assets" / "views").glob("*.js")):
        for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if "onEnter:" in line and "onInput:" not in line:
                offenders.append(f"{f.name}:{i}")
    if offenders:
        print("  以下筛选文本框只在回车时提交，点查询会丢条件：")
        for o in offenders:
            print("    - " + o)
        return False
    print("  -> 通过（筛选文本框都在输入时写入筛选状态）")
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
    checks.append(("emoji / 装饰符号禁令", check_no_emoji))
    checks.append(("embed 目录一致性（web/ 必须全部进 git）", check_embed_tracked))
    checks.append(("控制台前后端参数契约（前端发的过滤条件后端必须读）", check_api_contract))
    checks.append(("控制台筛选条件接线（文本框必须输入即提交）", check_filter_inputs_commit_on_input))
    checks.append(("热路径零分配门禁（BenchmarkEngine_NoMatch）", check_alloc_gate))

    failed = [name for name, fn in checks if not step(name, fn)]

    print()
    if failed:
        print("门禁未通过：" + "、".join(failed))
        return 1
    print("门禁全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())

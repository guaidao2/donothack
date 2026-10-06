#!/usr/bin/env python3
"""打包发布产物。

产出（dist/release/）：
    donothack_<版本>_linux_amd64.tar.gz     —— 目标平台（低配 VPS 绝大多数是 x86_64）
    donothack_<版本>_linux_arm64.tar.gz     —— arm64 VPS（不少廉价机型）
    donothack_<版本>_windows_amd64.zip      —— 本机调试用
    SHA256SUMS                              —— 校验和

每个包内都是"解开就能跑"的完整一份：

    donothack              二进制（CGO 关、-trimpath、去符号）
    rules/                 出厂规则集（**没有 embed 进二进制，必须随包发布**）
    config.example.yaml    配置模板（每行带注释，是配置的权威说明）
    README.md              唯一的产品文档
    LICENSE                许可（自用免费，禁止转售）

为什么要固化成脚本而不是手敲命令：
  1. 版本号/提交号/构建时间要注入到二进制里（`donothack version` 会打印），
     手敲容易漏掉某一个平台；
  2. `GOAMD64=v1` 是硬要求（低配 VPS 的 CPU 常不支持 AVX2，默认的 v3 会直接崩），
     漏了就得到一个"一启动就 illegal instruction"的包；
  3. 规则集必须随包走 —— 漏了的话二进制起得来但一条规则都没有，看起来像"WAF 不拦"。
"""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIST = ROOT / "dist" / "release"

# 打进每个包的公共文件
PAYLOAD = ["rules", "config.example.yaml", "README.md", "LICENSE"]

# 目标平台：(GOOS, GOARCH, GOAMD64)
TARGETS = [
    ("linux", "amd64", "v1"),   # 主要交付目标
    ("linux", "arm64", ""),     # GOAMD64 只对 amd64 有效
    ("windows", "amd64", "v1"), # 本机调试用
]


def run(cmd: list[str], env: dict[str, str]) -> None:
    r = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print(f"失败：{' '.join(cmd)}")
        print(r.stdout or "")
        print(r.stderr or "")
        raise SystemExit(1)


def git(*args: str) -> str:
    r = subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    return (r.stdout or "").strip()


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="donothack 发布打包")
    ap.add_argument("--version", default=None,
                    help="版本号（默认取 git describe --tags，取不到就用 0.0.0-dev）")
    ap.add_argument("--only", default=None, help="只构建某个平台，如 linux/amd64")
    args = ap.parse_args()

    version = args.version or git("describe", "--tags", "--always") or "0.0.0-dev"
    commit = git("rev-parse", "--short", "HEAD") or "unknown"
    date = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    print(f"版本 {version}  提交 {commit}  构建时间 {date}")
    print(f"Go: {shutil.which('go') or '未找到 go'}")

    # 记住"构建前 dist/release 里有什么"，便于只列本次产物
    DIST.mkdir(parents=True, exist_ok=True)

    built: list[tuple[str, pathlib.Path, int]] = []
    for goos, goarch, goamd64 in TARGETS:
        if args.only and args.only != f"{goos}/{goarch}":
            continue

        pkg = f"donothack_{version}_{goos}_{goarch}"
        stage = DIST / pkg
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True)

        binname = "donothack.exe" if goos == "windows" else "donothack"
        binpath = stage / binname

        env = dict(os.environ)
        env.update({
            "CGO_ENABLED": "0",       # 静态二进制，不依赖 glibc 版本
            "GOOS": goos,
            "GOARCH": goarch,
            "GOFLAGS": "-trimpath",
        })
        if goamd64:
            env["GOAMD64"] = goamd64
        else:
            env.pop("GOAMD64", None)

        ldflags = (f"-s -w "
                   f"-X donothack/internal/version.Version={version} "
                   f"-X donothack/internal/version.Commit={commit} "
                   f"-X donothack/internal/version.Date={date}")
        run(["go", "build", "-trimpath", "-ldflags", ldflags, "-o", str(binpath),
             "./cmd/donothack"], env)

        for item in PAYLOAD:
            src = ROOT / item
            dst = stage / item
            if src.is_dir():
                shutil.copytree(src, dst)
            else:
                shutil.copy2(src, dst)

        # 打包
        if goos == "windows":
            archive = DIST / f"{pkg}.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
                for f in sorted(stage.rglob("*")):
                    if f.is_file():
                        z.write(f, f.relative_to(DIST))
        else:
            archive = DIST / f"{pkg}.tar.gz"
            with tarfile.open(archive, "w:gz") as t:
                t.add(stage, arcname=pkg)

        shutil.rmtree(stage)  # 只留压缩包，避免 dist 里堆一堆展开的目录
        size = archive.stat().st_size
        built.append((pkg, archive, size))
        print(f"  打好 {archive.name}  {size / 1024 / 1024:.1f} MiB")

    if not built:
        print("没有构建任何平台（--only 写错了？）")
        return 1

    # 校验和
    sums = DIST / "SHA256SUMS"
    lines = []
    for pkg, path, _ in built:
        lines.append(f"{sha256(path)}  {path.name}")
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"\n校验和写入 {sums.relative_to(ROOT)}：")
    for line in lines:
        print("  " + line)

    print("\n各平台包里都有：donothack（二进制）+ rules/ + config.example.yaml + README.md + LICENSE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

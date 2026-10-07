"""门禁：控制台前端发出去的**查询参数**，后端必须有对应的读取。

为什么需要这条：前端一直发 `ip=` / `rule=`，后端只读 `client_ip` / `rule_id` ——
名字对不上**又不报错**，表现是"填了客户端 IP 却返回全部事件"。
这类静默忽略靠人点界面查不全，所以用静态对账把它变成门禁。

判据：对每个"前端用 query 调用"的端点，`前端发送的查询参数 - 后端读取的参数` 必须为空。

注意两个坑（都踩过）：
  1. api.js 的写法是 `name: (params) => request('/path', { query: params })`，
     不是 `name: request(...)`；正则写错会让对账数变成 0，门禁"永远通过"。
  2. 路由表带 `/api/v1` 前缀，api.js 不带 —— 必须对齐，否则每个端点都找不到 handler。
另外只统计 `query:` 形式的调用，避免把 POST body 的字段当成查询参数（会产生大量误报）。
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
API_JS = ROOT / "web" / "assets" / "api.js"
VIEWS = ROOT / "web" / "assets" / "views"
BACKEND = ROOT / "internal" / "console"

# 分页/格式类参数：后端在读，但不一定出现在列出的 handler 里
GLOBAL_OK = {"range", "cursor", "limit", "format", "offset"}


def api_methods() -> dict[str, tuple[str, bool, set[str]]]:
    """api.js：方法名 -> (路径, 是否用 query 传参, query 里内联声明的参数名)。"""
    out: dict[str, tuple[str, bool, set[str]]] = {}
    for line in API_JS.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s{2}(\w+)\s*:\s*(?:\([^)]*\)\s*=>\s*)?request\(\s*'([^']+)'(.*)$", line)
        if m:
            rest = m.group(3)
            inline: set[str] = set()
            qm = re.search(r"query:\s*\{([^}]*)\}", rest)
            if qm:
                inline = object_keys(qm.group(1))
            out[m.group(1)] = (m.group(2), "query:" in rest, inline)
    return out


def object_keys(text: str) -> set[str]:
    """对象字面量里的键：既认 `k: v`，也认 `{ limit, cursor }` 这种简写。"""
    keys = set(re.findall(r"(?:^|[{,\s])([a-z_]+)\s*:", text))
    keys |= set(re.findall(r"(?:^|[{,\s])([a-z_]+)\s*(?=[,}])", text))
    return keys


def local_builders(text: str) -> dict[str, set[str]]:
    """页面里构造查询对象的函数/变量：`function params() { ... }` / `const query = {...}`。

    用花括号配平取函数体 —— 靠缩进或 `\\n  }` 之类的正则会在别的排版下静默失配，
    参数名解析成空集，门禁就"假通过"了（这个坑本轮踩过两次）。
    """
    out: dict[str, set[str]] = {}
    for m in re.finditer(r"function\s+(\w+)\s*\([^)]*\)\s*\{", text):
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        body = text[start:i]
        names = set(re.findall(r"\bout\.([a-z_]+)\s*=", body)) | object_keys(body)
        out[m.group(1)] = names
    for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*\{([^}]*)\}", text):
        out.setdefault(m.group(1), set()).update(object_keys(m.group(2)))
    # 变量间接：`const query = params();` 这类再指一层（视图里普遍这么写）
    for _ in range(3):
        for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*\(\s*\)", text):
            if m.group(2) in out:
                out.setdefault(m.group(1), set()).update(out[m.group(2)])
        for m in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*(\w+)\s*;", text):
            if m.group(2) in out:
                out.setdefault(m.group(1), set()).update(out[m.group(2)])
    return out


def frontend_sent() -> tuple[dict[str, set[str]], set[str]]:
    """返回 (端点 -> 前端查询参数名, 解析不出来的端点集合)。"""
    methods = api_methods()
    sent: dict[str, set[str]] = {}
    unresolved: set[str] = set()
    for f in sorted(VIEWS.glob("*.js")):
        text = f.read_text(encoding="utf-8")
        builders = local_builders(text)
        for call in re.finditer(r"api\.(\w+)\(([^;]*?)\)\s*[;.,)]", text):
            name, args = call.group(1), call.group(2)
            entry = methods.get(name)
            if entry is None or not entry[1]:
                continue  # 不是 query 形式的调用
            path = entry[0]
            inline = entry[2]
            if args.strip() == "":
                sent.setdefault(path, set()).update(inline)
                continue
            names: set[str] = set(inline)
            resolved = bool(inline)
            for m in re.finditer(r"\{([^}]*)\}", args):  # 内联对象字面量
                names |= object_keys(m.group(1))
                resolved = True
            for ident in re.findall(r"\b(\w+)\b", args):  # params() / query 这种变量
                if ident in builders:
                    names |= builders[ident]
                    resolved = True
            if not resolved:
                # 参数名解析不出来 = 结论未知，不能当通过
                unresolved.add(path)
            sent.setdefault(path, set()).update(names)
    return sent, unresolved


def route_handlers() -> dict[str, str]:
    """console.go：`h("/api/v1/x", s.handleY)` -> 去掉前缀的路径到 handler。

    跳过以 `/` 结尾的子路径注册（`/api/v1/rules/`），否则它会把集合端点覆盖掉。
    """
    out: dict[str, str] = {}
    text = (BACKEND / "console.go").read_text(encoding="utf-8")
    for m in re.finditer(r'h\(\s*"(/api/v1/[^"]+)"\s*,\s*s\.(\w+)\s*\)', text):
        raw = m.group(1)
        if raw.endswith("/"):
            continue
        out[raw.removeprefix("/api/v1")] = m.group(2)
    return out


def backend_accepted(handler: str) -> set[str]:
    """handler 自己读的查询参数名 + 它显式调用的、接收 q 的辅助函数读的。

    只扫 handler 自己的函数体：整个文件一起扫会把别的 handler 的参数算进来，
    变成"看起来很宽"的假通过。
    """
    body = ""
    whole = ""
    for f in BACKEND.glob("*.go"):
        if f.name.endswith("_test.go"):
            continue
        t = f.read_text(encoding="utf-8")
        m = re.search(r"func \(s \*Server\) " + re.escape(handler) + r"\(([\s\S]*?)\n\}", t)
        if m:
            body, whole = m.group(0), t
            break
    if not body:
        return set()

    def names_in(src: str) -> set[str]:
        out: set[str] = set()
        out |= set(re.findall(r'q\.Get\("([a-z_]+)"\)', src))
        out |= set(re.findall(r'query(?:Int|Bool|String)\(r,\s*"([a-z_]+)"', src))
        for m in re.finditer(r"pick\(([^)]*)\)", src):
            out |= set(re.findall(r'"([a-z_]+)"', m.group(1)))
        return out

    names = names_in(body)
    # handler 显式调用到的、会读查询参数的本地函数（filterRules / filterAuditRows /
    # eventQueryFrom …）。**按"handler 真的调了它"来收**，而不是整个文件一起扫 ——
    # 后者会把别的 handler 的参数算进来，变成假通过。
    readers: dict[str, set[str]] = {}
    for fm in re.finditer(r"func (\w+)\(([^)]*)\)[^{]*\{([\s\S]*?)\n\}", whole):
        fname, params, fbody = fm.group(1), fm.group(2), fm.group(3)
        if not re.search(r"\bq\b|\burl\.Values\b", fbody):
            continue
        readers[fname] = names_in(fbody) | (names_in(params) if "url.Values" in params else set())
    for cm in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body):
        got = readers.get(cm.group(1))
        if got:
            names |= got
    return names


def handler_source(handler: str) -> str:
    """取出某个 handler 的函数体（与 backend_accepted 同一套匹配方式）。"""
    for f in BACKEND.glob("*.go"):
        if f.name.endswith("_test.go"):
            continue
        t = f.read_text(encoding="utf-8")
        m = re.search(r"func \(s \*Server\) " + re.escape(handler) + r"\(([\s\S]*?)\n\}", t)
        if m:
            return m.group(0)
    return ""


def get_response_keys(handler: str) -> set[str]:
    """handler 的 GET 分支里写进响应的**顶层**键。

    顶层是与写接口对账的单位：嵌套对象（stats 之类）整体进整体出，不算一个字段。
    只认两种写法：`out["k"] = ...` 与 `map[string]any{ "k": ... }` 里 depth==1 的键 ——
    直接扫 `"k":` 会把嵌套 map 的子键（keys/banned/…）也算进来，变成一堆假问题。
    """
    src = handler_source(handler)
    if not src:
        return set()
    i = src.find("case http.MethodGet")
    if i < 0:
        return set()
    j = src.find("case http.Method", i + 10)
    seg = src[i : j if j > 0 else len(src)]

    keys = set(re.findall(r'\bout\["([a-z_][a-z0-9_]*)"\]\s*=', seg))
    pos = 0
    while True:
        m = seg.find("map[string]any{", pos)
        if m < 0:
            break
        start = seg.find("{", m)
        depth = 0
        k = start
        end = len(seg)
        found: set[str] = set()
        while k < len(seg):
            c = seg[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = k
                    break
            elif c == '"' and depth == 1:
                km = re.match(r'"([a-z_][a-z0-9_]*)"\s*:', seg[k:])
                if km:
                    found.add(km.group(1))
                    k += len(km.group(0)) - 1
            k += 1
        pos = end + 1
        if found:
            # 第一段**非空**的响应 map 就是响应形状；嵌套 map（stats 之类）不再单独取键。
            keys |= found
            break
    return keys


def write_request_keys(handler: str) -> set[str]:
    """handler 的解码结构体里的 json 标签 —— 严格解码下这就是白名单。"""
    src = handler_source(handler)
    return set(re.findall(r'`json:"([^",]+)', src)) if src else set()


# "编辑整份配置"的端点对：控制台把 GET 的响应回填进编辑框、再整体提交。
# 判据：**GET 会发的每个顶层字段，写接口的解码结构体里必须都有** —— 没有白名单、
# 没有"忽略列表"。派生/只读字段（stats、ban_window_s 之类）也要写进结构体里收下，
# 那正是"读回来能原样提交"这条预期的实现方式。
#
# 为什么不留忽略列表：第一版留了，结果它把要抓的东西放过了 ——
# 清空后端兼容字段、门禁照样绿，因为忽略列表正好覆盖了那几个名字。
#（同一个坑在 SSE 事件名门禁上踩过一次：只要存在能容纳错误写法的白名单分支，
# 就要问自己"这个分支是不是正好放过我要抓的"。）
#
# 不钉这条会怎样（本轮真实发生）：GET /ratelimit 多了 ban_window_s / ban_duration_s /
# stats，用户只是改了一个数字就得到"请求体不是合法 JSON"，看着像格式错误。
ROUNDTRIP = [
    ("/ratelimit", "/ratelimit"),
    ("/notify", "/notify"),
]


def roundtrip_problems() -> list[str]:
    problems: list[str] = []
    routes = route_handlers()
    for get_path, put_path in ROUNDTRIP:
        get_handler = routes.get(get_path)
        put_handler = routes.get(put_path)
        if not get_handler or not put_handler:
            problems.append(f"{get_path} / {put_path}：路由对不上，无法判定（未知≠通过）")
            continue
        emitted = get_response_keys(get_handler)
        accepted = write_request_keys(put_handler)
        if not emitted or not accepted:
            problems.append(f"{get_path} / {put_path}：字段解析不出来，无法判定（未知≠通过）")
            continue
        missing = sorted(emitted - accepted)
        if missing:
            problems.append(
                f"{put_path}（{put_handler}）：GET 会发但这些字段写接口不收 —— "
                + ", ".join(missing)
                + "；派生/只读字段也要在解码结构体里收下并忽略，否则编辑框读回来改一下再提交会报格式错误"
            )
    return problems


def main() -> int:
    routes = route_handlers()
    sent, unresolved_paths = frontend_sent()
    problems: list[str] = []
    checked = 0
    for path, names in sorted(sent.items()):
        handler = routes.get(path)
        if handler is None:
            continue
        accepted = backend_accepted(handler)
        checked += 1
        if not names and path in unresolved_paths:
            # 解析不出参数名 = 结论未知。**未知不能当通过** ——
            # 上一版就是这里静默放过，才让"过滤条件被忽略"继续存在。
            problems.append(f"{path}（{handler}）：解析不出前端参数名，无法判定")
            continue
        missing = sorted(n for n in names if n not in accepted and n not in GLOBAL_OK)
        if missing:
            problems.append(f"{path}（{handler}）：前端发了但后端没读 —— {', '.join(missing)}")

    print(f"  对账端点数：{checked}")
    if checked == 0:
        print("  -> 失败：一个端点都没对上，说明门禁自己坏了（不是通过）")
        return 1

    # 第二块：编辑往返契约（GET 回填 → 整体提交）
    roundtrip = roundtrip_problems()
    print(f"  编辑往返端点对：{len(ROUNDTRIP)}")
    if roundtrip:
        problems.extend(roundtrip)

    if problems:
        print("  前端过滤条件问题：")
        for p in problems:
            print("    - " + p)
        return 1
    print("  -> 通过（前端发送的查询参数后端都有对应读取；编辑往返字段也对得上）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

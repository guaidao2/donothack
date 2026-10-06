package blockpage

// builtinHTML 是内置拦截页。
//
// 硬性约束（改这个模板前先读）：
//  1. **零外部资源**：没有字体、CDN、图片、JS。站点被攻击时可能本来就半死不活，
//     拦截页再去拉外部资源只会白屏或长时间转圈。
//  2. **不用 JavaScript**：既避免 CSP 麻烦，也避免"攻击者页面里我们自己的脚本"这类问题。
//  3. **只展示白名单字段**，且全部经 html/template 上下文转义。
//     尤其 `Host` 与 `Path` 是攻击者可控制的，绝不能直接拼。
//  4. **不暴露规则 ID 与命中细节**：那等于免费教人绕过。只给类目级别的说明。
//  5. **深浅色自适应**：用 prefers-color-scheme，别让夜里运维被白屏晃眼。
//
// 控制台可以用自定义模板整体替换它（见 blockpage.Options.CustomHTML）。
const builtinHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Title}}</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f5f6f8;
    --card: #ffffff;
    --fg: #16181d;
    --muted: #6b7280;
    --line: #e5e7eb;
    --accent: #b42318;
    --accent-bg: #fef3f2;
    --brand: #1f2937;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1115;
      --card: #171a21;
      --fg: #e8eaed;
      --muted: #9aa3af;
      --line: #262b35;
      --accent: #ff8a80;
      --accent-bg: #2a1a1a;
      --brand: #cbd5e1;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: var(--bg);
    color: var(--fg);
    font: 15px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
          "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  }
  .card {
    width: 100%;
    max-width: 620px;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 32px 32px 24px;
  }
  .code {
    display: inline-block;
    font: 600 13px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    color: var(--accent);
    background: var(--accent-bg);
    border-radius: 6px;
    padding: 6px 10px;
    margin-bottom: 14px;
  }
  h1 { font-size: 21px; margin: 0 0 8px; letter-spacing: .2px; }
  p.lead { margin: 0 0 22px; color: var(--muted); }
  dl {
    margin: 0;
    border-top: 1px solid var(--line);
    padding-top: 16px;
    display: grid;
    grid-template-columns: 92px 1fr;
    gap: 8px 16px;
    font-size: 13.5px;
  }
  dt { color: var(--muted); }
  dd {
    margin: 0;
    word-break: break-all;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12.5px;
  }
  .hint {
    margin-top: 22px;
    padding: 12px 14px;
    border: 1px solid var(--line);
    border-radius: 8px;
    color: var(--muted);
    font-size: 13px;
  }
  .hint strong { color: var(--fg); font-weight: 600; }
  footer {
    margin-top: 24px;
    padding-top: 14px;
    border-top: 1px solid var(--line);
    display: flex;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    color: var(--muted);
    font-size: 12.5px;
  }
  .brand { color: var(--brand); font-weight: 600; }
  a { color: inherit; }
  @media (max-width: 480px) {
    .card { padding: 24px 20px 18px; }
    dl { grid-template-columns: 1fr; gap: 2px 0; }
    dt { margin-top: 8px; }
  }
</style>
</head>
<body>
  <main class="card">
    <span class="code">{{.Status}} {{.StatusText}}</span>
    <h1>{{.Title}}</h1>
    <p class="lead">
      这次请求被安全策略拦截了。如果你认为这是误判，请把下面的请求 ID 提供给站点管理员，
      他们可以据此在审计日志里定位这次请求。
    </p>

    <dl>
      <dt>请求 ID</dt><dd>{{.TxID}}</dd>
      <dt>时间</dt><dd>{{.Time}}</dd>
      {{if .Host}}<dt>站点</dt><dd>{{.Host}}</dd>{{end}}
      {{if .Path}}<dt>路径</dt><dd>{{.Method}} {{.Path}}</dd>{{end}}
      {{if .Category}}<dt>命中类目</dt><dd>{{.CategoryLabel}}</dd>{{end}}
      {{if .RetryAfter}}<dt>建议等待</dt><dd>{{.RetryAfter}} 秒</dd>{{end}}
    </dl>

    <div class="hint">
      <strong>为什么会看到这个页面？</strong>
      请求里包含了被判定为攻击特征的参数、请求体或请求头。
      常见原因包括：链接里的特殊字符被安全策略误判、程序自动发送的扫描流量、
      或者表单内容里含有被拦截的关键字。
      {{if .Contact}}<br>申诉与联系：{{.Contact}}{{end}}
    </div>

    {{if .Branding}}
    <footer>
      <span>Protected by <span class="brand">{{.ProductName}}</span>{{if .Version}} {{.Version}}{{end}}</span>
      {{if .ProductURL}}<span><a href="{{.ProductURL}}" rel="noopener noreferrer">{{.ProductURL}}</a></span>{{end}}
    </footer>
    {{end}}
  </main>
</body>
</html>
`

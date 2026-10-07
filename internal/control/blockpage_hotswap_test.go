package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"donothack/internal/blockpage"
)

// 控制台改完模板后，**数据面渲染的那一份必须跟着换**。
//
// 这条是端到端验证时差点误判的路径：GET /block-page 显示 custom=true 不等于
// 数据面已经换了 —— 中间隔着"mutation 造新 renderer → Apply 推给 pipeline"两步，
// 任何一步漏了，控制台看着改好了、线上还是旧页。
func TestSetBlockPageHTMLChangesRenderedPage(t *testing.T) {
	const marker = "HOT-SWAP-MARKER"

	cur := &State{
		BlockPage: BlockPageState{
			Options:  blockpage.Options{Status: 403, Branding: true, Title: "旧标题"},
			Renderer: blockpage.New(blockpage.Options{Status: 403, Branding: true, Title: "旧标题"}),
		},
	}

	next, _, err := SetBlockPageHTML{HTML: "<h1>" + marker + "</h1><p>{{.CategoryLabel}}</p>"}.Apply(cur)
	if err != nil {
		t.Fatalf("替换模板不该失败：%v", err)
	}
	if next.BlockPage.Renderer == nil {
		t.Fatal("新状态里的 Renderer 是 nil —— 数据面拿到的仍是旧渲染器")
	}
	if next.BlockPage.Renderer == cur.BlockPage.Renderer {
		t.Fatal("Renderer 没有被换掉（指针相同）—— 控制台改了但数据面不会变")
	}
	if got := next.BlockPage.CustomHTML; !strings.Contains(got, marker) {
		t.Fatalf("状态里的模板不是刚提交的那份：%q", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/vulnerabilities/sqli/?id=1", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	r := next.BlockPage.Renderer
	r.Respond(rec, req, r.NewData(req, "tx-1", "sqli", "SQLI-4001", "127.0.0.1", 403, 0), false)

	body := rec.Body.String()
	if !strings.Contains(body, marker) {
		t.Fatalf("渲染结果里没有自定义模板的内容：%s", body)
	}
	if !strings.Contains(body, "SQL 注入") {
		t.Fatalf("模板里的 {{.CategoryLabel}} 没有被替换：%s", body)
	}
	if rec.Code != 403 {
		t.Fatalf("拦截状态码应为 403，实际 %d", rec.Code)
	}
}

// 编译不过的模板必须整次拒绝，不能换上去。
func TestSetBlockPageHTMLRejectsBrokenTemplate(t *testing.T) {
	cur := &State{
		BlockPage: BlockPageState{
			Options:  blockpage.Options{Status: 403},
			Renderer: blockpage.New(blockpage.Options{Status: 403}),
		},
	}
	before := cur.BlockPage.Renderer
	next, _, err := SetBlockPageHTML{HTML: "<h1>{{.NoSuchField}}</h1>"}.Apply(cur)
	if err == nil {
		t.Fatal("字段不存在的模板应当被拒绝")
	}
	if next != nil {
		t.Fatal("被拒绝的变更不该返回新状态")
	}
	if cur.BlockPage.Renderer != before {
		t.Fatal("拒绝后原渲染器不该被动过")
	}
}

package console

import (
	"net/url"
	"testing"
	"time"
)

// 前端一直发 q/category/severity/enabled/file，后端以前一个都不读 ——
// "按文件、类目、严重度筛选"全是摆设。这条把过滤语义钉住。
func TestFilterRules(t *testing.T) {
	list := []ruleView{
		{ID: "RCE-6001", Message: "命令注入", Category: "rce", Severity: "high", Enabled: true,
			File: "rules/40-rce.yaml", Source: "rules/40-rce.yaml:206", Tags: []string{"rce", "cmdi"}},
		{ID: "SQLI-4001", Message: "联合查询注入", Category: "sqli", Severity: "critical", Enabled: false,
			File: "rules/20-sqli.yaml", Source: "rules/20-sqli.yaml:12", Tags: []string{"sqli"}},
		{ID: "XSS-5001", Message: "脚本标签", Category: "xss", Severity: "high", Enabled: true,
			File: "rules/30-xss.yaml", Source: "rules/30-xss.yaml:30"},
	}
	ids := func(v []ruleView) []string {
		out := make([]string, 0, len(v))
		for _, r := range v {
			out = append(out, r.ID)
		}
		return out
	}
	cases := []struct {
		query string
		want  int
	}{
		{"", 3},
		{"category=rce", 1},
		{"severity=high", 2},
		{"enabled=false", 1},
		{"enabled=1", 2},
		{"file=40-rce", 1},
		{"q=sql", 1},
		{"q=cmdi", 1}, // 标签命中
		{"category=rce&severity=critical", 0},
	}
	for _, c := range cases {
		q, err := url.ParseQuery(c.query)
		if err != nil {
			t.Fatal(err)
		}
		got := filterRules(list, q)
		if len(got) != c.want {
			t.Errorf("%q 期望 %d 条，实际 %d 条（%v）", c.query, c.want, len(got), ids(got))
		}
	}
}

func TestFilterAuditRows(t *testing.T) {
	now := time.Now()
	rows := []auditRow{
		{At: now, Actor: "admin", Action: "engine.set", OK: true, Target: "mode"},
		{At: now, Actor: "admin", Action: "login", OK: false, Remote: "1.2.3.4"},
		{At: now, Actor: "ops", Action: "config.reload", OK: true, Detail: "rules=62"},
	}
	cases := []struct {
		query string
		want  int
	}{
		{"", 3},
		{"actor=ops", 1},
		{"action=login", 1},
		{"result=ok", 2},
		{"result=failed", 1},
		{"target=rules", 1}, // 落在 Detail 上
		{"actor=admin&result=ok", 1},
	}
	for _, c := range cases {
		q, err := url.ParseQuery(c.query)
		if err != nil {
			t.Fatal(err)
		}
		if got := filterAuditRows(rows, q); len(got) != c.want {
			t.Errorf("%q 期望 %d 条，实际 %d 条", c.query, c.want, len(got))
		}
	}
}

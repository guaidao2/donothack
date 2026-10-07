package console

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"donothack/internal/eventstore"
)

// 前端曾经发 `ip=` / `rule=`，后端只读 `client_ip` / `rule_id` —— 名字不一致又不报错，
// 于是"填了客户端 IP 却返回全部事件"。这条测试把两边的名字都钉住。
func TestEventQueryFromAcceptsAliases(t *testing.T) {
	parse := func(q string) url.Values {
		v, err := url.ParseQuery(q)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	got := eventQueryFrom(parse("client_ip=1.2.3.4&rule_id=SQLI-4001"), 50)
	if got.ClientIP != "1.2.3.4" || got.RuleID != "SQLI-4001" {
		t.Errorf("规范名没映射上：%+v", got)
	}
	got = eventQueryFrom(parse("ip=5.6.7.8&rule=RCE-6003"), 50)
	if got.ClientIP != "5.6.7.8" || got.RuleID != "RCE-6003" {
		t.Errorf("别名没映射上：%+v", got)
	}

	// 时间范围：前端发 range=1h|6h|24h|7d，后端以前完全不认，等于这个下拉从来没生效。
	got = eventQueryFrom(parse("range=24h"), 50)
	if got.Since.IsZero() {
		t.Fatal("range=24h 没有转成 Since")
	}
	if ago := time.Since(got.Since); ago < 23*time.Hour || ago > 25*time.Hour {
		t.Errorf("24h 窗口算错了：%v", ago)
	}
	got = eventQueryFrom(parse("range=7d"), 50)
	if ago := time.Since(got.Since); ago < 6*24*time.Hour || ago > 8*24*time.Hour {
		t.Errorf("7d 窗口算错了：%v", ago)
	}
	if got = eventQueryFrom(parse(""), 50); !got.Since.IsZero() {
		t.Errorf("没给范围时不该设 Since：%v", got.Since)
	}
	// since 显式给了就优先于 range
	explicit := time.Now().Add(-90 * time.Minute).UTC().Truncate(time.Second)
	got = eventQueryFrom(parse("since="+explicit.Format(time.RFC3339)+"&range=24h"), 50)
	if !got.Since.Equal(explicit) {
		t.Errorf("显式 since 应优先，期望 %v 实际 %v", explicit, got.Since)
	}
}

// 端到端：往事件存储塞两条不同来源的事件，再按 IP 过滤取出来。
func TestEventsEndpointFiltersByClientIP(t *testing.T) {
	s := newTestConsole(t)
	if s.o.Events == nil {
		s.o.Events = eventstore.New(eventstore.DefaultOptions())
	}
	for _, ip := range []string{"1.1.1.1", "9.9.9.9"} {
		s.o.Events.Add(eventstore.Event{
			ID: "e-" + ip, Ts: time.Now(), TxID: "t-" + ip, ClientIP: ip,
			Method: "GET", Host: "app.example.com", Path: "/x", Proto: "HTTP/1.1",
			Status: 403, RuleID: "RCE-6001", Category: "rce", Verdict: "block",
		})
	}

	id, csrf, err := s.session.create("admin", "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(query string) []any {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18081/api/v1/events"+query, nil)
		req.Host = "127.0.0.1:18081"
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
		req.AddCookie(&http.Cookie{Name: csrfCookie, Value: signCSRF(s.secret, csrf)})
		rec := httptest.NewRecorder()
		s.handleEvents(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s 应 200，实际 %d：%s", query, rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		items, _ := out["events"].([]any)
		return items
	}

	for _, q := range []string{"?client_ip=1.1.1.1", "?ip=1.1.1.1"} {
		items := fetch(q)
		if len(items) != 1 {
			t.Fatalf("%s 应只返回 1 条，实际 %d 条（过滤没生效？）", q, len(items))
		}
		first, _ := items[0].(map[string]any)
		if got, _ := first["client_ip"].(string); got != "1.1.1.1" {
			t.Errorf("%s 过滤后拿到的是 %q", q, got)
		}
	}
	if items := fetch(""); len(items) != 2 {
		t.Errorf("不带过滤应返回 2 条，实际 %d", len(items))
	}
}

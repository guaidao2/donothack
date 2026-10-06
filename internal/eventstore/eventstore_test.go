package eventstore

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func newStore(t *testing.T, ring int) (*Store, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	s := New(Options{RingSize: ring, PayloadLimit: 64, Now: clk.Now})
	return s, clk
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func ev(id, verdict, category, ip string) Event {
	return Event{ID: id, TxID: id, Verdict: verdict, Category: category, ClientIP: ip, Path: "/x"}
}

// ring 必须有界：超过容量就覆盖最旧的。
func TestRingIsBounded(t *testing.T) {
	s, _ := newStore(t, 8)
	for i := 0; i < 50; i++ {
		s.Add(ev(fmt.Sprintf("e%02d", i), "block", "sqli", "1.1.1.1"))
	}
	if s.Len() != 8 {
		t.Errorf("ring 条数应为 8，实际 %d", s.Len())
	}
	if s.Total() != 50 {
		t.Errorf("总数应为 50（不受淘汰影响），实际 %d", s.Total())
	}
	// 最新的应当在，最旧的应当被覆盖
	if _, ok := s.Get("e49"); !ok {
		t.Error("最新事件应当还在")
	}
	if _, ok := s.Get("e00"); ok {
		t.Error("最旧事件应当已被覆盖")
	}
}

func TestListNewestFirstAndCursor(t *testing.T) {
	s, _ := newStore(t, 100)
	for i := 0; i < 10; i++ {
		s.Add(ev(fmt.Sprintf("e%02d", i), "block", "sqli", "1.1.1.1"))
	}
	page1, cursor := s.List(Query{Limit: 3})
	if len(page1) != 3 {
		t.Fatalf("第一页应有 3 条，实际 %d", len(page1))
	}
	if page1[0].ID != "e09" {
		t.Errorf("最新在前，首条应为 e09，实际 %s", page1[0].ID)
	}
	if cursor == "" {
		t.Fatal("应当返回下一页游标")
	}
	page2, _ := s.List(Query{Limit: 3, Cursor: cursor})
	if len(page2) != 3 {
		t.Fatalf("第二页应有 3 条，实际 %d", len(page2))
	}
	if page2[0].ID == page1[2].ID {
		t.Error("分页不该重复上页内容")
	}
	// 翻到底
	seen := map[string]bool{}
	cur := ""
	for i := 0; i < 20; i++ {
		list, next := s.List(Query{Limit: 3, Cursor: cur})
		for _, e := range list {
			if seen[e.ID] {
				t.Errorf("事件 %s 出现了两次", e.ID)
			}
			seen[e.ID] = true
		}
		if next == "" {
			break
		}
		cur = next
	}
	if len(seen) != 10 {
		t.Errorf("应当翻到全部 10 条，实际 %d", len(seen))
	}
}

func TestQueryFilters(t *testing.T) {
	s, _ := newStore(t, 100)
	s.Add(Event{ID: "a", Verdict: "block", Category: "sqli", ClientIP: "1.1.1.1", Path: "/login", RuleID: "SQLI-1", Detail: "union"})
	s.Add(Event{ID: "b", Verdict: "log", Category: "xss", ClientIP: "2.2.2.2", Path: "/comment", RuleID: "XSS-1"})
	s.Add(Event{ID: "c", Verdict: "pass", Category: "", ClientIP: "1.1.1.1", Path: "/index"})

	cases := []struct {
		name string
		q    Query
		want []string
	}{
		{"按裁决", Query{Verdict: "block"}, []string{"a"}},
		{"按类目", Query{Category: "xss"}, []string{"b"}},
		{"按 IP", Query{ClientIP: "1.1.1.1"}, []string{"c", "a"}},
		{"按路径子串", Query{PathContains: "login"}, []string{"a"}},
		{"按规则", Query{RuleID: "XSS-1"}, []string{"b"}},
		{"只看拦截", Query{OnlyBlocked: true}, []string{"a"}},
		{"搜索", Query{Search: "union"}, []string{"a"}},
		{"搜索命中 IP", Query{Search: "2.2.2.2"}, []string{"b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := s.List(c.q)
			if len(got) != len(c.want) {
				t.Fatalf("命中 %d 条，期望 %d 条：%+v", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i].ID != c.want[i] {
					t.Errorf("第 %d 条 = %s，期望 %s", i, got[i].ID, c.want[i])
				}
			}
		})
	}
}

func TestTimeRangeFilter(t *testing.T) {
	s, clk := newStore(t, 100)
	s.Add(ev("old", "block", "sqli", "1.1.1.1"))
	clk.Advance(time.Hour)
	s.Add(ev("new", "block", "sqli", "1.1.1.1"))

	got, _ := s.List(Query{Since: clk.Now().Add(-time.Minute)})
	if len(got) != 1 || got[0].ID != "new" {
		t.Errorf("时间过滤失效：%+v", got)
	}
	got2, _ := s.List(Query{Until: clk.Now().Add(-time.Minute)})
	if len(got2) != 1 || got2[0].ID != "old" {
		t.Errorf("Until 过滤失效：%+v", got2)
	}
}

// payload 必须可打印化并截断（\xNN 转义、不切碎 UTF-8）。
func TestPayloadPrintableAndClipped(t *testing.T) {
	s, _ := newStore(t, 10)
	s.Add(Event{
		ID:            "p1",
		Verdict:       "block",
		PayloadBefore: "a\x00b\xffc\ttab",
		PayloadAfter:  strings.Repeat("x", 200),
	})
	e, ok := s.Get("p1")
	if !ok {
		t.Fatal("找不到事件")
	}
	if !strings.Contains(e.PayloadBefore, `\x00`) || !strings.Contains(e.PayloadBefore, `\xff`) {
		t.Errorf("控制字符应当转成 \\xNN：%q", e.PayloadBefore)
	}
	if strings.ContainsRune(e.PayloadBefore, 0) {
		t.Error("原文里的 NUL 不该留在展示副本里")
	}
	if len(e.PayloadAfter) > 64 {
		t.Errorf("payload 副本应被截断到 64 字节，实际 %d", len(e.PayloadAfter))
	}
	if !e.PayloadTruncated {
		t.Error("截断后应当标记 truncated")
	}
}

// 中文等多字节字符不能被截断成半个字符。
func TestPayloadDoesNotSplitUTF8(t *testing.T) {
	got, _ := clipPrintable(strings.Repeat("中", 50), 10)
	if !isValidUTF8(got) {
		t.Errorf("截断后出现非法 UTF-8：%q", got)
	}
}

func isValidUTF8(s string) bool {
	for i := 0; i < len(s); {
		r, n := decodeRune(s[i:])
		if r == 0 || n == 0 {
			return false
		}
		i += n
	}
	return true
}

func TestTimeseriesFillsGaps(t *testing.T) {
	s, clk := newStore(t, 100)
	s.Add(ev("a", "block", "sqli", "1.1.1.1"))
	clk.Advance(2 * time.Minute)
	s.Add(ev("b", "log", "xss", "1.1.1.1"))

	pts := s.Timeseries(5)
	if len(pts) != 5 {
		t.Fatalf("应当返回 5 个点，实际 %d", len(pts))
	}
	// 最后一个点是当前分钟：1 条
	if pts[4].Total != 1 {
		t.Errorf("当前分钟应为 1，实际 %d", pts[4].Total)
	}
	// 两分钟前是第一条
	if pts[2].Total != 1 {
		t.Errorf("两分钟前应为 1，实际 %d", pts[2].Total)
	}
	// 中间一分钟没有事件，应当补 0 而不是缺位
	if pts[3].Total != 0 {
		t.Errorf("空分钟应当为 0，实际 %d", pts[3].Total)
	}
}

func TestSummaryAndRankings(t *testing.T) {
	s, _ := newStore(t, 100)
	s.Add(ev("a", "block", "sqli", "1.1.1.1"))
	s.Add(ev("b", "block", "sqli", "1.1.1.1"))
	s.Add(ev("c", "log", "xss", "2.2.2.2"))
	s.Add(ev("d", "pass", "", "3.3.3.3"))

	sum := s.Summary()
	if sum.Total != 4 || sum.Blocked != 2 {
		t.Errorf("统计不对：%+v", sum)
	}
	if sum.ByVerdict["block"] != 2 {
		t.Errorf("block 计数 = %d", sum.ByVerdict["block"])
	}
	if sum.ByCategory["sqli"] != 2 {
		t.Errorf("sqli 计数 = %d", sum.ByCategory["sqli"])
	}
	cats := s.Categories()
	if len(cats) < 2 || cats[0].Key != "sqli" {
		t.Errorf("类目排行应按数量倒序：%+v", cats)
	}
	tops := s.TopIPs(2)
	if len(tops) != 1 || tops[0].Key != "1.1.1.1" || tops[0].N != 2 {
		t.Errorf("来源排行只统计被拦事件：%+v", tops)
	}
}

func TestClear(t *testing.T) {
	s, _ := newStore(t, 10)
	for i := 0; i < 5; i++ {
		s.Add(ev(fmt.Sprintf("e%d", i), "block", "sqli", "1.1.1.1"))
	}
	if n := s.Clear(); n != 5 {
		t.Errorf("应当清掉 5 条，实际 %d", n)
	}
	if s.Len() != 0 {
		t.Error("清空后应当为空")
	}
	// 总数不清（那是"自启动以来"的计数）
	if s.Total() != 5 {
		t.Errorf("Total 不该被清空：%d", s.Total())
	}
}

func TestGetByTxID(t *testing.T) {
	s, _ := newStore(t, 10)
	s.Add(Event{ID: "evt-1", TxID: "tx-1", Verdict: "block"})
	if _, ok := s.Get("tx-1"); !ok {
		t.Error("应当能按事务 ID 查")
	}
	if _, ok := s.Get("不存在"); ok {
		t.Error("不存在的 ID 不该返回")
	}
}

func BenchmarkAdd(b *testing.B) {
	s := New(Options{RingSize: 512})
	e := Event{TxID: "t", Verdict: "block", Category: "sqli", Path: "/x"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Add(e)
	}
}

func TestBlockingVerdicts(t *testing.T) {
	for _, v := range []string{"block", "drop", "tarpit", "challenge", "ratelimit", "banned"} {
		if !isBlocking(v) {
			t.Errorf("%s 应当算被处置", v)
		}
	}
	for _, v := range []string{"pass", "log", ""} {
		if isBlocking(v) {
			t.Errorf("%s 不该算被处置", v)
		}
	}
}

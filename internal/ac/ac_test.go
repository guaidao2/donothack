package ac

import (
	"fmt"
	"strings"
	"testing"
)

// 每条注册的模式都必须能被找到。
//
// 这个测试是为了钉住一类非常隐蔽的 bug：建自动机时如果持有了会失效的
// 切片指针，新边会被写到废弃的旧数组上，表现成"某些模式永远匹配不上"。
func TestMatcherFindsEveryPattern(t *testing.T) {
	patterns := []string{
		"union select",
		"union",
		"select",
		"information_schema",
		"/sdk/weblanguage",
		"metadata.google.internal",
		"zzz-last-pattern",
		"a",
		"ab",
		"abc",
		"/acunetix-wvs-test-for-some-inexistent-file",
	}
	pats := make([]Pattern, 0, len(patterns))
	for i, p := range patterns {
		pats = append(pats, Pattern{Literal: []byte(p), ID: int32(i)})
	}
	m := New(pats)

	for i, p := range patterns {
		hay := []byte("prefix-" + p + "-suffix")
		found := false
		m.Scan(hay, func(id int32, _ int) bool {
			if id == int32(i) {
				found = true
				return false
			}
			return true
		})
		if !found {
			t.Errorf("模式 %q 没有被匹配到（自动机丢边了）", p)
		}
	}
}

// 模式多到逼着底层数组反复扩容时，仍然每条都能匹配。
func TestMatcherManyPatternsAfterReallocation(t *testing.T) {
	const n = 800
	patterns := make([]string, n)
	pats := make([]Pattern, n)
	for i := 0; i < n; i++ {
		patterns[i] = fmt.Sprintf("pattern-%04d-marker", i)
		pats[i] = Pattern{Literal: []byte(patterns[i]), ID: int32(i)}
	}
	m := New(pats)

	for i := 0; i < n; i += 37 { // 抽样，避免测试太慢
		found := m.MatchAny([]byte("xx " + patterns[i] + " yy"))
		if !found {
			t.Errorf("扩容之后模式 %q 匹配不到", patterns[i])
		}
	}
	if m.Patterns() != n {
		t.Errorf("模式数 = %d，期望 %d", m.Patterns(), n)
	}
}

// 一个模式的输出链必须能被完整报告（字典后缀链不能漏）。
func TestMatcherReportsOverlappingPatterns(t *testing.T) {
	m := New([]Pattern{
		{Literal: []byte("ab"), ID: 1},
		{Literal: []byte("abc"), ID: 2},
		{Literal: []byte("bc"), ID: 3},
	})
	seen := map[int32]bool{}
	m.Scan([]byte("abc"), func(id int32, _ int) bool {
		seen[id] = true
		return true
	})
	for _, want := range []int32{1, 2, 3} {
		if !seen[want] {
			t.Errorf("扫描 abc 时模式 %d 没被报告；实际报告了 %v", want, seen)
		}
	}
}

// 跨边界匹配（模式被输入切分成两段时要靠 fail 链找回）。
func TestMatcherHandlesFailLinks(t *testing.T) {
	m := New([]Pattern{
		{Literal: []byte("abcd"), ID: 1},
		{Literal: []byte("bcde"), ID: 2},
		{Literal: []byte("cdef"), ID: 3},
	})
	seen := map[int32]bool{}
	m.Scan([]byte("abcdef"), func(id int32, _ int) bool {
		seen[id] = true
		return true
	})
	if len(seen) != 3 {
		t.Errorf("三条模式都应当命中，实际 %v", seen)
	}
}

func TestMatcherEmptyAndNoPatterns(t *testing.T) {
	m := New(nil)
	if m.MatchAny([]byte("anything")) {
		t.Error("没有模式时不应命中")
	}
	if m.Patterns() != 0 {
		t.Errorf("模式数应为 0，实际 %d", m.Patterns())
	}
	// 空模式必须被忽略（否则会在每个输入上命中）
	m2 := New([]Pattern{{Literal: nil, ID: 9}, {Literal: []byte("x"), ID: 10}})
	if m2.Patterns() != 1 {
		t.Errorf("空模式应被忽略，模式数 = %d", m2.Patterns())
	}
}

func TestMatcherEndOffset(t *testing.T) {
	m := New([]Pattern{{Literal: []byte("abc"), ID: 1}})
	var got int
	m.Scan([]byte("xxabcxx"), func(_ int32, end int) bool {
		got = end
		return false
	})
	if got != 4 {
		t.Errorf("命中结束下标应为 4（'c' 的位置），实际 %d", got)
	}
	if strings.TrimSpace("") != "" {
		t.Fatal("unreachable")
	}
}

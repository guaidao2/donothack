package engine

import (
	"context"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"donothack/internal/parser"
	"donothack/internal/rules"
	"donothack/internal/tx"
)

// 性能门禁：
//
//	BenchmarkEngine_NoMatch  0 allocs/op，< 20µs/op
//
// 这两条是**硬门禁**，不是"尽量"。没有它，"热路径零分配"就只是一句口号 ——
// 这次补上之前，文档里写着这条门禁，代码里却根本没有对应的基准。
//
// 测试用规则集刻意覆盖多种算子（pm / regex / detectSQLi / contains），
// 这样预筛、变换链、算子三条路径都被走到。

const benchRules = `
version: 1
meta:
  name: bench
  author: test
rules:
  - id: BENCH-SQLI
    phase: 2
    severity: critical
    category: sqli
    message: "union select"
    targets:
      - collection: ARGS
    transforms: [replaceComments, urlDecode, compressWhitespace, lowercase]
    operator:
      name: pm
      params:
        patterns: ["union select", "or 1=1", "information_schema", "sleep("]
    test:
      positive: ["1 union select 2"]
      negative: ["a normal value", "another normal one"]
  - id: BENCH-SEMANTIC
    phase: 2
    severity: critical
    category: sqli
    message: "语义 SQLi"
    targets:
      - collection: ARGS
    transforms: [urlDecode, lowercase]
    operator:
      name: detectSQLi
    test:
      positive: ["1' union select 1,2--"]
      negative: ["it's a good day", "select your country"]
  - id: BENCH-XSS
    phase: 2
    severity: high
    category: xss
    message: "xss"
    targets:
      - collection: ARGS
      - collection: REQUEST_BODY
    transforms: [urlDecode, htmlEntityDecode, lowercase]
    operator:
      name: regex
      params:
        pattern: '<script[^>]{0,64}>'
    test:
      positive: ["<script>alert(1)</script>"]
      negative: ["plain text", "another plain one"]
  - id: BENCH-SCAN
    phase: 1
    severity: low
    category: scanner
    message: "scanner"
    targets:
      - collection: REQUEST_HEADERS
        selector: "user-agent"
    transforms: [lowercase]
    operator:
      name: pm
      params:
        patterns: ["sqlmap", "nikto", "nmap", "acunetix", "nessus"]
    test:
      positive: ["sqlmap/1.7"]
      negative: ["Mozilla/5.0", "curl/8.0"]
`

func benchRuleSet(b *testing.B) *rules.RuleSet {
	b.Helper()
	dir := b.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		b.Fatal(err)
	}
	p := filepath.Join(dir, "bench.yaml")
	if err := os.WriteFile(p, []byte(benchRules), 0o644); err != nil {
		b.Fatal(err)
	}
	rs, err := rules.LoadFiles(rules.DefaultOptions(), []string{p})
	if err != nil {
		b.Fatalf("加载基准规则集失败：%v", err)
	}
	return rs
}

func newBenchEngine(b *testing.B, rs *rules.RuleSet) *Engine {
	b.Helper()
	return New(Options{
		RuleSet:          rs,
		Mode:             "block",
		InboundThreshold: 5,
		Limits:           parser.DefaultLimits(),
	})
}

// BenchmarkEngine_NoMatch 是**门禁基准**：正常业务请求（不命中任何规则）。
//
// 判据：0 allocs/op，< 20µs/op。
func BenchmarkEngine_NoMatch(b *testing.B) {
	eng := newBenchEngine(b, benchRuleSet(b))
	// 请求只构造一次：httptest.NewRequest 自身的分配不该算进引擎账上。
	// 无 body 的 GET 可以被 Process 反复处理（它不改动请求）。
	req := httptest.NewRequest("GET", "http://shop.example.com/api/v1/items?page=2&size=20&sort=price", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cookie", "session=abc123; csrf=xyz789")

	tr := &tx.Transaction{}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Reset()
		if _, err := eng.Process(ctx, tr, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEngine_NoMatchJSON 带 JSON body 但不命中：变换链与 JSON 展开都要走到。
func BenchmarkEngine_NoMatchJSON(b *testing.B) {
	eng := newBenchEngine(b, benchRuleSet(b))
	body := `{"user":{"name":"alice","tags":["a","b","c"]},"page":2,"note":"hello world"}`
	req := httptest.NewRequest("POST", "http://shop.example.com/api/v1/items", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")

	tr := &tx.Transaction{}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Reset()
		req.Body = io.NopCloser(strings.NewReader(body))
		if _, err := eng.Process(ctx, tr, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEngine_NoMatchManyHeaders 头部多、参数多：预筛要扫更多值。
func BenchmarkEngine_NoMatchManyHeaders(b *testing.B) {
	eng := newBenchEngine(b, benchRuleSet(b))
	req := httptest.NewRequest("GET", "http://shop.example.com/search?q=shoes&page=3&size=40&sort=price&filter=red&brand=nike", nil)
	for i := 0; i < 12; i++ {
		req.Header.Set("X-Custom-"+string(rune('A'+i)), "value-with-some-length")
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")

	tr := &tx.Transaction{}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Reset()
		if _, err := eng.Process(ctx, tr, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEngine_Hit 命中一条规则：这条路径允许分配（要建事件、要记分）。
func BenchmarkEngine_Hit(b *testing.B) {
	eng := newBenchEngine(b, benchRuleSet(b))
	body := "id=1&q=" + url.QueryEscape("1' UNION SELECT password FROM users--")
	req := httptest.NewRequest("POST", "http://shop.example.com/search", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")

	tr := &tx.Transaction{}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Reset()
		req.Body = io.NopCloser(strings.NewReader(body))
		if _, err := eng.Process(ctx, tr, req); err != nil {
			b.Fatal(err)
		}
	}
}

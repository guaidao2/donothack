package operator

import (
	"strings"
	"testing"
)

// 病态输入下的 CPU 放大基准。
//
// 跑法：
//
//	go test ./internal/operator/ -run ^$ -bench 'SemanticPathological' -benchmem
//
// slow 版本就是修复前那版实现（无 O(n) 前置判断），保留它作对照 ——
// 这样"修了到底快多少"是量出来的，不是我说的。
func BenchmarkSemanticPathologicalQuoteComment(b *testing.B) {
	s := strings.Repeat("'", 256<<10)
	b.SetBytes(int64(len(s)))

	b.Run("fixed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if quoteThenComment(s) {
				b.Fatal("不该命中")
			}
		}
	})
	b.Run("slow_old", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if quoteThenCommentSlow(s) {
				b.Fatal("不该命中")
			}
		}
	})
}

func BenchmarkSemanticPathologicalStacked(b *testing.B) {
	s := strings.Repeat(";", 256<<10)
	b.SetBytes(int64(len(s)))

	b.Run("fixed", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if stackedQuery(s) {
				b.Fatal("不该命中")
			}
		}
	})
	b.Run("slow_old", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if stackedQuerySlow(s) {
				b.Fatal("不该命中")
			}
		}
	})
}

// quoteThenCommentSlow / stackedQuerySlow 是修复前的实现，只作基准对照。
func quoteThenCommentSlow(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '\'' && s[i] != '"' {
			continue
		}
		rest := s[i+1:]
		if len(rest) > 64 {
			rest = rest[:64]
		}
		if strings.Contains(rest, "--") || strings.HasPrefix(strings.TrimSpace(rest), "#") ||
			strings.Contains(rest, "/*") {
			return true
		}
	}
	return false
}

func stackedQuerySlow(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != ';' {
			continue
		}
		rest := strings.TrimSpace(s[i+1:])
		for _, kw := range stackedKeywords {
			if strings.HasPrefix(rest, kw) {
				return true
			}
		}
	}
	return false
}

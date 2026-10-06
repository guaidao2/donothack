package engine

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"donothack/internal/parser"
	"donothack/internal/rules"
	"donothack/internal/tx"
)

// 这一组测试对应两条审计发现：
//
//	04-F4  mixed 模式的**类目阈值不参与裁决** —— `thresholdFor` 只在"是否提前停阶段"
//	       里用过，真正裁决的 `decide` 直接看 InboundThreshold；而且
//	       `CategoryThresholds` 一直没有数据源，mixed 静默等价于 block。
//	03-F3  `/config/reload` 宣称 engine.mode 能热改，实际引擎根本收不到 ——
//	       应急切 block 会拿到"已热改"而 WAF 还在 detect。
//
// 两条都用同一个规则集（分数可控），从"引擎裁决"这一端断言。

const mixedRules = `
version: 1
meta:
  name: mixed
  author: test
rules:
  - id: T-XSS
    phase: 2
    severity: high
    category: xss
    score: 6
    message: "xss"
    targets: [{collection: ARGS}]
    transforms: [lowercase]
    operator: {name: pm, params: {patterns: ["<script"]}}
    test: {positive: ["<script>alert(1)</script>"], negative: ["a normal value", "another normal one"]}
  - id: T-SQLI
    phase: 2
    severity: high
    category: sqli
    score: 6
    message: "sqli"
    targets: [{collection: ARGS}]
    transforms: [lowercase]
    operator: {name: pm, params: {patterns: ["union select"]}}
    test: {positive: ["1 union select 2"], negative: ["a normal value", "another normal one"]}
`

func mixedEngine(t *testing.T, mode string, cat map[string]int) *Engine {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "mixed.yaml")
	if err := os.WriteFile(p, []byte(mixedRules), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := rules.LoadFiles(rules.DefaultOptions(), []string{p})
	if err != nil {
		t.Fatalf("加载规则失败：%v", err)
	}
	return New(Options{
		RuleSet:            rs,
		Mode:               mode,
		InboundThreshold:   5,
		CategoryThresholds: cat,
		Limits:             parser.DefaultLimits(),
	})
}

func runEngine(t *testing.T, e *Engine, target string) (verdict string, score int) {
	t.Helper()
	req := httptest.NewRequest("GET", "http://x/"+target, nil)
	tr := &tx.Transaction{}
	dec, err := e.Process(context.Background(), tr, req)
	if err != nil {
		t.Fatalf("Process 失败：%v", err)
	}
	return dec.Verdict.String(), dec.Score
}

// mixed：类目阈值**高**于分数 → 只记录；**低**于分数 → 拦截。
//
// 这就是的两个方向：原先两个方向都错
// （本该只记的被 403、本该拦的只 log），因为裁决只看全局阈值 5，而分数是 6。
func TestMixedModeUsesCategoryThresholds(t *testing.T) {
	// xss 阈值 100（分数 6 远不够）→ 只记录
	e := mixedEngine(t, "mixed", map[string]int{"xss": 100, "sqli": 100})
	v, score := runEngine(t, e, "?q=%3Cscript%3Ealert(1)%3C/script%3E")
	if score != 6 {
		t.Fatalf("分数应为 6，实际 %d", score)
	}
	if v == "block" {
		t.Errorf("类目阈值 100 而分数 6：mixed 下**不该**拦截（原实现会 403），实际 %s", v)
	}
	if v != "log" {
		t.Errorf("应当只记录（log），实际 %s", v)
	}

	// xss 阈值 4（分数 6 够）→ 拦截
	e2 := mixedEngine(t, "mixed", map[string]int{"xss": 4, "sqli": 4})
	v2, _ := runEngine(t, e2, "?q=%3Cscript%3Ealert(1)%3C/script%3E")
	if v2 != "block" {
		t.Errorf("类目阈值 4 而分数 6：mixed 下应当拦截，实际 %s", v2)
	}

	// 没配阈值的类目回落全局阈值 5 → 分数 6 够 → 拦截
	e3 := mixedEngine(t, "mixed", map[string]int{"xss": 100})
	v3, _ := runEngine(t, e3, "?q=1+union+select+2")
	if v3 != "block" {
		t.Errorf("未配阈值的类目应回落全局阈值（5），分数 6 应当拦截，实际 %s", v3)
	}
}

// 热改模式：从 detect 切到 block，**下一个请求就要生效**。
//
// 这是的回归 —— 原先控制台会回"已热改"，而引擎还在 detect。
func TestHotModeSwitchTakesEffectImmediately(t *testing.T) {
	e := mixedEngine(t, "detect", nil)

	// detect：命中只记录，绝不拦
	if v, _ := runEngine(t, e, "?q=1+union+select+2"); v == "block" {
		t.Fatalf("detect 模式不该拦截，实际 %s", v)
	}

	// 热改到 block（模拟 /config/reload → control.Apply → ApplyEngine）
	e.SetTunables(Tunables{
		Mode:             "block",
		InboundThreshold: 5,
	})

	// 同一个引擎实例，下一个请求必须开始拦
	if v, _ := runEngine(t, e, "?q=1+union+select+2"); v != "block" {
		t.Fatalf("切到 block 之后同一个引擎必须立刻开始拦截，实际 %s", v)
	}

	// 再切回 detect，也必须立刻生效（应急开关要能双向用）
	e.SetTunables(Tunables{Mode: "detect", InboundThreshold: 5})
	if v, _ := runEngine(t, e, "?q=1+union+select+2"); v == "block" {
		t.Fatalf("切回 detect 之后不该再拦截，实际 %s", v)
	}
}

// 热改阈值：同一个类目、同样的分数，只改阈值就该改变裁决。
func TestHotThresholdSwitchTakesEffect(t *testing.T) {
	e := mixedEngine(t, "block", nil)
	if v, _ := runEngine(t, e, "?q=1+union+select+2"); v != "block" {
		t.Fatalf("阈值 5、分数 6 应当拦截，实际 %s", v)
	}
	e.SetTunables(Tunables{Mode: "block", InboundThreshold: 50})
	if v, _ := runEngine(t, e, "?q=1+union+select+2"); v == "block" {
		t.Fatalf("阈值提到 50 之后不该再拦截，实际 %s", v)
	}
}

// SetTunables 要能容忍零值（配置留空），并且 Decision.Mode 也跟着热改。
func TestSetTunablesDefaultsAndDecisionMode(t *testing.T) {
	e := mixedEngine(t, "detect", nil)
	e.SetTunables(Tunables{}) // 全零
	tun := e.Tunables()
	if tun.Mode != "detect" {
		t.Errorf("Mode 零值应回落 detect，实际 %q", tun.Mode)
	}
	if tun.InboundThreshold != 5 {
		t.Errorf("InboundThreshold 零值应回落 5，实际 %d", tun.InboundThreshold)
	}

	e.SetTunables(Tunables{Mode: "block"})
	req := httptest.NewRequest("GET", "http://x/?q=ok", nil)
	tr := &tx.Transaction{}
	dec, err := e.Process(context.Background(), tr, req)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Mode != "block" {
		t.Errorf("裁决里回报的模式应当是热改后的 block，实际 %q", dec.Mode)
	}
	if !strings.Contains(dec.Reason, "") { // 只是确保 Reason 不 panic
		t.Log(dec.Reason)
	}
}

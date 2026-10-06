package operator

import (
	"strings"
	"testing"

	"donothack/internal/kv"
)

// 弱信号与强信号必须能**分开打分**。
//
// 背景：`quote probing`（值本身就是引号、或 `1'`）和 `boolean comparison`
// （`1 AND 1=2`）走的是同一个 `detectSQLi` 算子。而规则是整条给分的，
// 所以这两类指纹原先都在同一条 5 分规则里 —— 于是"值里只有一个引号"
// 单独就够阈值拦截，成了设计文档明确要避免的"一个单引号封站"
// （搜索框里搜一个引号字符是正常行为）。
//
// 修法是给算子加指纹过滤，让强信号留在 5 分规则、弱信号单列一条 2 分规则。
func TestDetectSQLiFingerprintFilter(t *testing.T) {
	eval := func(t *testing.T, params map[string]any, in string) (bool, string) {
		t.Helper()
		op, err := Compile("detectSQLi", kv.Params(params))
		if err != nil {
			t.Fatalf("编译失败：%v", err)
		}
		res, err := op.Eval(&EvalCtx{RuleID: "T", Phase: 2}, []byte(in))
		if err != nil {
			t.Fatalf("求值失败：%v", err)
		}
		return res.Matched, res.Detail
	}

	// 只看弱指纹：引号形态命中，强特征不命中
	onlyWeak := map[string]any{"fingerprints": []any{"quote probing"}}
	for _, in := range []string{"'", `"`, "1'", "''''"} {
		if hit, detail := eval(t, onlyWeak, in); !hit {
			t.Errorf("只看 quote probing 时 %q 应当命中（%s）", in, detail)
		}
	}
	for _, in := range []string{"1 union select 2", "1 AND 1=2", "1'--"} {
		if hit, _ := eval(t, onlyWeak, in); hit {
			t.Errorf("只看 quote probing 时 %q 不该命中（那是别的指纹）", in)
		}
	}

	// 排除弱指纹：强特征照常命中，引号形态不命中
	noWeak := map[string]any{"exclude_fingerprints": []any{"quote probing"}}
	for _, in := range []string{"1 union select 2", "1 AND 1=2", "1'--", "1; drop table x--"} {
		if hit, detail := eval(t, noWeak, in); !hit {
			t.Errorf("排除 quote probing 后 %q 仍应命中（%s）", in, detail)
		}
	}
	for _, in := range []string{"'", `"`, "1'"} {
		if hit, _ := eval(t, noWeak, in); hit {
			t.Errorf("排除 quote probing 后 %q 不该命中", in)
		}
	}

	// 不过滤时二者都命中（默认行为不变）
	for _, in := range []string{"'", "1 union select 2", "1 AND 1=2"} {
		if hit, _ := eval(t, map[string]any{}, in); !hit {
			t.Errorf("不过滤时 %q 应当命中", in)
		}
	}

	// 正常业务：怎么配都不该命中
	for _, in := range []string{"O'Brien", "it's a nice day", "Rock'n'Roll", "Levi's 501"} {
		for _, params := range []map[string]any{{}, onlyWeak, noWeak} {
			if hit, detail := eval(t, params, in); hit {
				t.Errorf("正常业务 %q 不该命中（detail=%s）", in, detail)
			}
		}
	}
}

// 指纹名写错必须**在编译期报错**，而不是静默失效。
//
// 这与"未知算子参数要拒绝"是同一条纪律：规则作者写 `fingerprints: ["quote-probing"]`
// （少个下划线）时，如果只是不生效，他会以为自己调过关了。
func TestDetectSQLiRejectsUnknownFingerprint(t *testing.T) {
	for _, bad := range []map[string]any{
		{"fingerprints": []any{"quote-probing"}},
		{"fingerprints": []any{"不存在的指纹"}},
		{"exclude_fingerprints": []any{"union selectt"}},
	} {
		if _, err := Compile("detectSQLi", kv.Params(bad)); err == nil {
			t.Errorf("%v 应当被拒绝（未知指纹名）", bad)
		} else if !strings.Contains(err.Error(), "未知的 SQL 注入指纹") {
			t.Errorf("错误信息应当点明是未知指纹，实际：%v", err)
		}
	}

	// 两个过滤器同时写会互相打架 → 拒绝
	if _, err := Compile("detectSQLi", kv.Params(map[string]any{
		"fingerprints": []any{"quote probing"}, "exclude_fingerprints": []any{"quote probing"},
	})); err == nil {
		t.Error("同时写 fingerprints 与 exclude_fingerprints 应当被拒绝")
	}

	// 合法名字要能编过（全部指纹名都认）
	for _, name := range sqliFingerprintNames {
		if _, err := Compile("detectSQLi", kv.Params(map[string]any{
			"fingerprints": []any{name},
		})); err != nil {
			t.Errorf("指纹名 %q 是合法的，不该被拒：%v", name, err)
		}
	}
}

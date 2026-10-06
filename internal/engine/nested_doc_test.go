package engine

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"donothack/internal/parser"
	"donothack/internal/rules"
	"donothack/internal/tx"
)

// 这一组测试是为一个**真实绕过**写的回归测试。
//
// crackweb 1.6.4 用 `?id=<base64(JSON)>` 的形式把 SQL 注入藏在编码后的参数文档里，
// 拿到了 Critical / High 两条 finding —— 而同样的 payload 明文放在普通参数里
// 是拦得住的。根因不是规则不认 SQL 注入，而是：
//
//	展开结果只写进了 ArgsJSON，而 59 条规则全都对着 ARGS（合并视图）匹配；
//	构造 ARGS 的 MergeInto 又发生在展开之前 —— 展开进了一个谁也看不到的副本。
//
// 教训：**测试只断言"展开函数产出了字段"是不够的，必须断言"规则能看到它"**。
// 下面这个测试就是从"规则能不能拦"这一端写的。

const nestedRules = `
version: 1
meta:
  name: nested
  author: test
rules:
  - id: T-SQLI
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
        patterns: ["union select", "and 1=1", "and 1=2", "sleep("]
    test:
      positive: ["1 union select 2"]
      negative: ["a normal value", "another normal one"]
`

func nestedEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "nested.yaml")
	if err := os.WriteFile(p, []byte(nestedRules), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := rules.LoadFiles(rules.DefaultOptions(), []string{p})
	if err != nil {
		t.Fatalf("加载规则失败：%v", err)
	}
	return New(Options{
		RuleSet:          rs,
		Mode:             "block",
		InboundThreshold: 5,
		Limits:           parser.DefaultLimits(),
		ExpandNestedDocs: true,
	})
}

func processGET(t *testing.T, eng *Engine, target string) Decision {
	t.Helper()
	req := httptest.NewRequest("GET", target, nil)
	tr := &tx.Transaction{}
	dec, err := eng.Process(context.Background(), tr, req)
	if err != nil {
		t.Fatalf("Process 出错：%v", err)
	}
	return dec
}

// urlEscape 只转义会破坏查询串的字节，其余原样（够测试用）。
func urlEscape(s string) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b = append(b, c)
		default:
			const hex = "0123456789ABCDEF"
			b = append(b, '%', hex[c>>4], hex[c&0x0f])
		}
	}
	return string(b)
}

func b64std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// 回归：明文 payload 能拦。
func TestNestedDocPlainPayloadBlocked(t *testing.T) {
	eng := nestedEngine(t)
	dec := processGET(t, eng, "http://x/user?id="+"1+UNION+SELECT+password+FROM+users--")
	if dec.Verdict != tx.VerdictBlock {
		t.Fatalf("明文 SQL 注入必须被拦，实际 %s（%s）", dec.Verdict, dec.Reason)
	}
}

// 回归：**同样的 payload 藏在 base64(JSON) 里也必须被拦。**
//
// 这条测试就是那个真实绕过的看门人：crackweb 用 `?id=<base64({"id":"..."})>`
// 拿到了 Critical finding。修好之前这里必然失败。
func TestNestedDocBase64JSONPayloadBlocked(t *testing.T) {
	eng := nestedEngine(t)
	inner := `{"uid":1,"ml":"1","id":"1 UNION SELECT password FROM users--"}`
	target := "http://x/user/id-b64-json?id=" + b64std(inner)
	dec := processGET(t, eng, target)
	if dec.Verdict != tx.VerdictBlock {
		var keys []string
		tr := &tx.Transaction{}
		req := httptest.NewRequest("GET", target, nil)
		ps := &parser.Scratch{}
		parser.ParseRequest(tr, req, ps, parser.DefaultLimits())
		parser.ExpandNestedDocs(&tr.Vars, ps, parser.DefaultLimits())
		tr.Vars.Args.ForEach(func(k, _ []byte) bool {
			keys = append(keys, string(k))
			return true
		})
		t.Fatalf("base64(JSON) 里的 SQL 注入必须被拦，实际 %s；ARGS 键=%v", dec.Verdict, keys)
	}
}

// 布尔盲注形态（crackweb 的另一条 finding）。
func TestNestedDocBooleanBlindBlocked(t *testing.T) {
	eng := nestedEngine(t)
	inner := `{"uid":1,"ml":"1","id":"1 AND 1=2"}`
	dec := processGET(t, eng, "http://x/user/id-b64-json?id="+b64std(inner))
	if dec.Verdict != tx.VerdictBlock {
		t.Fatalf("base64(JSON) 里的布尔盲注必须被拦，实际 %s", dec.Verdict)
	}
}

// 值本身是 JSON 文档（没有 base64 包装）时同样要能拦。
func TestNestedDocRawJSONPayloadBlocked(t *testing.T) {
	eng := nestedEngine(t)
	inner := `{"uid":1,"id":"1 UNION SELECT password FROM users--"}`
	target := "http://x/user?id=" + urlEscape(inner)
	dec := processGET(t, eng, target)
	if dec.Verdict != tx.VerdictBlock {
		t.Fatalf("JSON 文档参数里的 SQL 注入必须被拦，实际 %s", dec.Verdict)
	}
}

// 反面对照：正常的 base64(JSON) 参数不能误报。
func TestNestedDocBenignBase64JSONAllowed(t *testing.T) {
	eng := nestedEngine(t)
	inner := `{"uid":1,"ml":"1","page":2,"sort":"price"}`
	dec := processGET(t, eng, "http://x/user/id-b64-json?id="+b64std(inner))
	if dec.Verdict == tx.VerdictBlock {
		t.Fatalf("正常业务参数不该被拦：%s（%s）", dec.Verdict, dec.Reason)
	}
}

// 反面对照：base64 里是普通文本也不能拦。
func TestNestedDocBenignBase64TextAllowed(t *testing.T) {
	eng := nestedEngine(t)
	dec := processGET(t, eng, "http://x/user?note="+b64std("hello world from a normal user"))
	if dec.Verdict == tx.VerdictBlock {
		t.Fatalf("普通 base64 文本不该被拦：%s", dec.Verdict)
	}
}

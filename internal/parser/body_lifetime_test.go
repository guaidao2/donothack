package parser

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"donothack/internal/tx"
)

// 的回归测试：转发缓冲不能挂在解析用的 Scratch 上。
//
// 旧实现的形态：`ReadBodyForInspection` 把要转发的字节放进 `Scratch.Body`，
// 并 `r.Body = MultiReader(bytes.NewReader(buf), r.Body)`；而 `Engine.Process`
// 在返回前就 `sc.Reset(); pool.Put(sc)` —— 转发发生在返回**之后**。
// 于是同一块数组被下一个请求复用，`bytes.NewReader` 不拷贝，
// **A 请求的上游请求体会变成 B 的 body**（跨用户数据污染）。
//
// 这个测试把"引擎返回 → Scratch 回池 → 下一个请求复用同一块 Scratch"
// 这条时序显式演一遍，然后读**A 的** r.Body。
func TestForwardedBodySurvivesScratchReuse(t *testing.T) {
	sc := &Scratch{} // 故意复用同一块 Scratch，模拟池的行为
	lim := DefaultLimits()

	bodyA := "id=1&q=AAAA-payload-A"
	tA := &tx.Transaction{}
	reqA := httptest.NewRequest("POST", "http://x/save", strings.NewReader(bodyA))
	reqA.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ParseRequest(tA, reqA, sc, lim)

	// —— 引擎返回：Scratch 被 Reset 并回池（这里手动模拟）
	sc.Reset()

	bodyB := "id=2&q=BBBB-payload-B"
	tB := &tx.Transaction{}
	reqB := httptest.NewRequest("POST", "http://x/save", strings.NewReader(bodyB))
	reqB.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ParseRequest(tB, reqB, sc, lim)

	// —— 现在才轮到 A 的转发：读 A 的 r.Body，必须还是 A 的字节
	gotA, err := io.ReadAll(reqA.Body)
	if err != nil {
		t.Fatalf("读 A 的 body 失败：%v", err)
	}
	if string(gotA) != bodyA {
		t.Fatalf("A 的请求体被后来的请求污染了：\n  期望 %q\n  实际 %q", bodyA, string(gotA))
	}

	// B 的当然也要是 B 的
	gotB, err := io.ReadAll(reqB.Body)
	if err != nil {
		t.Fatalf("读 B 的 body 失败：%v", err)
	}
	if string(gotB) != bodyB {
		t.Fatalf("B 的请求体不对：期望 %q，实际 %q", bodyB, string(gotB))
	}
}

// 同一个事务被复用（对象池）：BodyBuf 截长度保留数组，第二次解析后
// 该请求自己的转发缓冲仍然必须正确 —— 不能因为复用就读到上一次的字节。
func TestBodyBufferReuseIsClean(t *testing.T) {
	lim := DefaultLimits()
	tr := &tx.Transaction{}
	sc := &Scratch{}

	first := "a=1&q=first-request-body"
	req1 := httptest.NewRequest("POST", "http://x/", strings.NewReader(first))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ParseRequest(tr, req1, sc, lim)
	if got, _ := io.ReadAll(req1.Body); string(got) != first {
		t.Fatalf("第一次解析后 body 不对：%q", got)
	}

	// 事务回池 → 复用（这正是 pipeline.pool 的行为）
	tr.Reset()

	second := "b=2&q=second-request-body-longer"
	req2 := httptest.NewRequest("POST", "http://x/", strings.NewReader(second))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ParseRequest(tr, req2, sc, lim)
	got, _ := io.ReadAll(req2.Body)
	if string(got) != second {
		t.Fatalf("复用后 body 不对（残留了上一次的字节？）：\n  期望 %q\n  实际 %q", second, string(got))
	}
	if !strings.Contains(string(got), "second") || strings.Contains(string(got), "first") {
		t.Fatalf("body 里混进了上一次请求的内容：%q", string(got))
	}
}

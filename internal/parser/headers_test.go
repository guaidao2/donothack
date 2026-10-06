package parser

import (
	"bufio"
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"donothack/internal/tx"
)

// 这条测试记录一个**决定检测能力的事实**：Go 的 net/http 在解析阶段就会
// 把 Transfer-Encoding 从 Header 里移走（放进 r.TransferEncoding），
// 并且在 chunked 时连 Content-Length 一起删掉。
//
// 后果（直接决定规则能写什么）：
//   - 任何针对 `Transfer-Encoding` / `Content-Length` 头做匹配的规则，
//     如果直接读 r.Header，**永远匹配不到** —— 死规则比没规则更糟，
//     因为它让人以为"我在防请求走私"。
//   - CL+TE 冲突（CL.TE / TE.CL 走私的前提）在本层**不可观测**：
//     Go 已经把它归一化掉了，所以歧义也传不到上游。
//     要检测它必须在 net/http 之前抓原始字节（未实现，记在 docs/DESIGN.md）。
//
// 所以 parser 会把这两个头按"解析后的语义"补进 Headers 集合，
// 让规则至少能看到 TE=chunked 与真实的 Content-Length。
func TestGoNormalizesContentLengthAndTransferEncoding(t *testing.T) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader([]byte(
		"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\nabc"))))
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if _, ok := req.Header["Content-Length"]; ok {
		t.Error("CL+TE 并存时 Go 应当删掉 Content-Length（本测试用来发现行为变化）")
	}
	if _, ok := req.Header["Transfer-Encoding"]; ok {
		t.Error("Go 应当把 Transfer-Encoding 从 Header 移走")
	}
	if req.ContentLength != -1 {
		t.Errorf("chunked 时 ContentLength 应为 -1，实际 %d", req.ContentLength)
	}
	if len(req.TransferEncoding) != 1 || !strings.EqualFold(req.TransferEncoding[0], "chunked") {
		t.Errorf("TransferEncoding 应保留 chunked，实际 %v", req.TransferEncoding)
	}
}

// 补回来之后，规则必须能在 Headers 集合里看到这两个头。
func TestParseRequestRestoresLengthHeaders(t *testing.T) {
	// chunked：应当能看到 transfer-encoding
	req := httptest.NewRequest("POST", "/x", strings.NewReader("3\r\nabc\r\n0\r\n\r\n"))
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = -1
	tr := &tx.Transaction{}
	ParseRequest(tr, req, &Scratch{}, DefaultLimits())
	if v, ok := tr.Vars.Headers.Get("transfer-encoding"); !ok || !strings.Contains(string(v), "chunked") {
		t.Errorf("Headers 里应补出 transfer-encoding，实际 %q ok=%v", v, ok)
	}

	// 普通请求：应当能看到真实 Content-Length
	req2 := httptest.NewRequest("POST", "/x", strings.NewReader("username=abc"))
	req2.Header.Set("Content-Length", "12")
	tr2 := &tx.Transaction{}
	ParseRequest(tr2, req2, &Scratch{}, DefaultLimits())
	if v, ok := tr2.Vars.Headers.Get("content-length"); !ok || string(v) != "12" {
		t.Errorf("Headers 里应有 content-length=12，实际 %q ok=%v", v, ok)
	}
}

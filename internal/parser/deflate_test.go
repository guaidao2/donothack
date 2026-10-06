package parser

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"net/http/httptest"
	"strings"
	"testing"

	"donothack/internal/tx"
)

// 的回归测试：`Content-Encoding: deflate` 必须按 **zlib** 解。
//
// 现实里两种实现都有：RFC 7230 指的是 zlib 包装（RFC 1950），
// 但有些客户端发裸 deflate 流（RFC 1951）。
// 旧实现只用裸流解析器 → **zlib 格式的正文 100% 解不开**，
// 而解压失败之后就退回"拿压缩字节去检测"，于是这类正文里的 payload 完全逃过检测。
func TestDeflateAcceptszlibWrapped(t *testing.T) {
	payload := "id=1' UNION SELECT password FROM users--"

	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	tr := &tx.Transaction{}
	req := httptest.NewRequest("POST", "/save", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Encoding", "deflate")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ParseRequest(tr, req, &Scratch{}, DefaultLimits())

	if len(tr.Vars.ParseErrors) != 0 {
		t.Fatalf("zlib 格式的 deflate 正文不该报解压失败：%v", tr.Vars.ParseErrors)
	}
	// 解压后的表单必须进了参数集合（否则规则看不到 payload）
	found := false
	tr.Vars.ArgsPost.ForEach(func(k, v []byte) bool {
		if bytes.Contains(v, []byte("UNION SELECT")) {
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Fatalf("zlib deflate 正文解压后应当进 ARGS_POST；实际键值：%s", dumpKeys(&tr.Vars.ArgsPost))
	}
}

// 裸 deflate 流（非 zlib 包装）也必须继续能解 —— 不能为了修 zlib 而弄坏另一种。
func TestDeflateStillAcceptsRawStream(t *testing.T) {
	payload := "q=raw-deflate-payload"

	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}

	tr := &tx.Transaction{}
	req := httptest.NewRequest("POST", "/save", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Encoding", "deflate")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ParseRequest(tr, req, &Scratch{}, DefaultLimits())

	if len(tr.Vars.ParseErrors) != 0 {
		t.Fatalf("裸 deflate 流不该报解压失败：%v", tr.Vars.ParseErrors)
	}
	got := ""
	tr.Vars.ArgsPost.ForEach(func(k, v []byte) bool {
		if strings.EqualFold(string(k), "q") {
			got = string(v)
			return false
		}
		return true
	})
	if got != "raw-deflate-payload" {
		t.Fatalf("裸 deflate 流解压结果不对：%q", got)
	}
}

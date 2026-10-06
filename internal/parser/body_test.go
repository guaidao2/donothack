package parser

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"

	"donothack/internal/tx"
)

func TestParseJSONFlattensNestedPaths(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	body := []byte(`{"user":{"name":"admin","roles":["a","b"]},"id":42,"ok":true,"nul":null}`)
	if err := ParseJSONInto(&p, sc, body, lim); err != nil {
		t.Fatalf("解析失败：%v", err)
	}

	want := map[string]string{
		"user.name":     "admin",
		"user.roles[0]": "a",
		"user.roles[1]": "b",
		"id":            "42",
		"ok":            "true",
		"nul":           "",
	}
	for k, v := range want {
		got, ok := p.Get(k)
		if !ok {
			t.Errorf("缺少键 %q（实际键：%s）", k, dumpKeys(&p))
			continue
		}
		if string(got) != v {
			t.Errorf("%s = %q，期望 %q", k, got, v)
		}
	}
}

// 深层嵌套里的 payload 必须能被看到 —— 攻击者把 payload 塞进三层数组也逃不掉。
func TestParseJSONFindsDeepPayload(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	body := []byte(`{"a":{"b":{"c":["safe","1' UNION SELECT password FROM users--"]}}}`)
	if err := ParseJSONInto(&p, sc, body, lim); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	found := false
	p.ForEach(func(k, v []byte) bool {
		if bytes.Contains(v, []byte("UNION SELECT")) {
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Errorf("深层嵌套里的 payload 没被展开出来；键：%s", dumpKeys(&p))
	}
}

func TestParseJSONRespectsDepthLimit(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxJSONDepth = 3
	var p tx.Params
	sc := &Scratch{}
	body := []byte(`{"a":{"b":{"c":{"d":{"e":"deep"}}}}}`)
	if err := ParseJSONInto(&p, sc, body, lim); err != nil {
		t.Fatalf("超深度不应报错（应当跳过），得到 %v", err)
	}
	if _, ok := p.Get("a.b"); ok {
		_ = ok // 深度内的容器本身不是叶子
	}
	if _, ok := p.Get("a.b.c.d.e"); ok {
		t.Error("超过深度上限的叶子不应被展开")
	}
}

func TestParseJSONRespectsNodeLimit(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxJSONNodes = 5
	var p tx.Params
	sc := &Scratch{}
	body := []byte(`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8}`)
	if err := ParseJSONInto(&p, sc, body, lim); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if p.Len() > 5 {
		t.Errorf("节点数应被限制为 5，实际 %d", p.Len())
	}
	if !p.Truncated() {
		t.Error("因为节点上限丢弃内容时必须标记")
	}
}

func TestParseJSONRejectsBroken(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	if err := ParseJSONInto(&p, sc, []byte(`{"a":`), lim); err == nil {
		t.Error("残缺 JSON 应当报错（由调用方记 parse_error），而不是静默通过")
	}
}

// crackweb 的「编码后的参数文档」手法：值是 base64(JSON)，payload 藏在字段里。
func TestParseBase64Document(t *testing.T) {
	lim := DefaultLimits()
	inner := `{"id":"1' OR 1=1--","q":"x"}`
	outer := base64.StdEncoding.EncodeToString([]byte(inner))

	var p tx.Params
	sc := &Scratch{}
	ok := ParseBase64DocInto(&p, sc, "payload", []byte(outer), lim, 1)
	if !ok {
		t.Fatal("base64 文档应当被展开")
	}
	found := false
	p.ForEach(func(k, v []byte) bool {
		if strings.Contains(string(v), "OR 1=1") {
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Errorf("base64 文档里的 payload 没被展开；键：%s", dumpKeys(&p))
	}
}

func TestParseBase64PlainText(t *testing.T) {
	lim := DefaultLimits()
	outer := base64.StdEncoding.EncodeToString([]byte("/etc/passwd"))
	var p tx.Params
	sc := &Scratch{}
	if !ParseBase64DocInto(&p, sc, "f", []byte(outer), lim, 1) {
		t.Fatal("可打印的 base64 文本也应作为派生值展开")
	}
	if _, ok := p.Get("f~b64"); !ok {
		t.Errorf("应生成 f~b64 派生键；实际：%s", dumpKeys(&p))
	}
}

func TestParseBase64DepthLimit(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxNestedDecode = 1
	inner := base64.StdEncoding.EncodeToString([]byte("hello world"))
	outer := base64.StdEncoding.EncodeToString([]byte(inner))
	var p tx.Params
	sc := &Scratch{}
	if ParseBase64DocInto(&p, sc, "f", []byte(outer), lim, 2) {
		t.Error("超过递归层数上限时不应继续展开")
	}
}

func TestParseXMLExpandsTextAndAttrs(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	body := []byte(`<root><user id="7">admin</user><q>1' OR 1=1--</q></root>`)
	hasDTD, err := ParseXMLInto(&p, sc, body, lim)
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if hasDTD {
		t.Error("这个文档没有 DTD")
	}
	if v, ok := p.Get("root.user"); !ok || string(v) != "admin" {
		t.Errorf("root.user = %q ok=%v；键：%s", v, ok, dumpKeys(&p))
	}
	if v, ok := p.Get("root.user@id"); !ok || string(v) != "7" {
		t.Errorf("属性应展开成 @id，得到 %q ok=%v", v, ok)
	}
}

// XXE 的载荷特征是 DTD/ENTITY 声明本身：必须如实报出来，交给规则记分。
//
// 注意这里**允许解析报错**：`&xxe;` 是未定义实体，Go 的 xml 会拒绝。
// 但 WAF 的正确行为是"报出 DTD + 报出解析错误"，而不是因为解析失败就当作没看见。
func TestParseXMLReportsDTD(t *testing.T) {
	lim := DefaultLimits()
	var p tx.Params
	sc := &Scratch{}
	body := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`)
	hasDTD, err := ParseXMLInto(&p, sc, body, lim)
	if !hasDTD {
		t.Errorf("含 ENTITY 的文档必须报告 hasDTD（err=%v）", err)
	}
}

func TestReadBodyGunzips(t *testing.T) {
	plain := []byte(`{"user":"admin' OR 1=1--"}`)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(plain)
	_ = zw.Close()

	req := httptest.NewRequest("POST", "/x", bytes.NewReader(buf.Bytes()))
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/json")

	sc := &Scratch{}
	var fwd, insp []byte // 生产里是 &t.BodyBuf / &t.InspectBuf，测试里给局部缓冲即可
	raw, inspect, truncated, errs := ReadBodyForInspection(req, sc, 1<<20, &fwd, &insp)
	if len(errs) != 0 {
		t.Fatalf("解压不应报错：%v", errs)
	}
	if truncated {
		t.Error("不该截断")
	}
	if !bytes.Equal(raw, buf.Bytes()) {
		t.Error("raw 必须是原始压缩字节（要原样转发给上游）")
	}
	if !bytes.Equal(inspect, plain) {
		t.Errorf("inspect 应当是解压后的内容，得到 %q", inspect)
	}
}

// 关键不变量：检测读了 body 之后，转发必须仍能拿到**完整**字节。
func TestReadBodyPreservesForwardableBytes(t *testing.T) {
	payload := []byte("field=value&other=1234")
	req := httptest.NewRequest("POST", "/x", bytes.NewReader(payload))

	sc := &Scratch{}
	var fwd, insp []byte
	// 上限故意设得很小，触发截断路径
	_, _, truncated, _ := ReadBodyForInspection(req, sc, 5, &fwd, &insp)
	if !truncated {
		t.Fatal("应当被截断")
	}
	rest, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("读取剩余 body 失败：%v", err)
	}
	if !bytes.Equal(rest, payload) {
		t.Errorf("转发内容被破坏：得到 %q，期望 %q", rest, payload)
	}
}

func TestParseMultipartSeparatesFilesAndFields(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("user", "admin' OR 1=1--")
	fw, _ := mw.CreateFormFile("upload", "../../shell.php.jpg")
	_, _ = fw.Write([]byte("<?php system($_GET['c']); ?>"))
	_ = mw.Close()

	lim := DefaultLimits()
	var params tx.Params
	var files tx.FileSet
	if err := ParseMultipartInto(&params, &files, mw.FormDataContentType(), buf.Bytes(), lim); err != nil {
		t.Fatalf("解析 multipart 失败：%v", err)
	}
	if v, ok := params.Get("user"); !ok || !strings.Contains(string(v), "OR 1=1") {
		t.Errorf("普通字段应进参数集合，得到 %q ok=%v", v, ok)
	}
	metas, ok := files["upload"]
	if !ok || len(metas) != 1 {
		t.Fatalf("文件部分应被记录，得到 %#v", files)
	}
	if metas[0].FileName != "../../shell.php.jpg" {
		t.Errorf("文件名 = %q（双扩展名要能被规则看到）", metas[0].FileName)
	}
	if !bytes.HasPrefix(metas[0].Magic[:metas[0].MagicLen], []byte("<?php")) {
		t.Errorf("魔数应当是 PHP 开头，得到 %q", metas[0].Magic[:metas[0].MagicLen])
	}
}

func dumpKeys(p *tx.Params) string {
	var sb strings.Builder
	p.ForEach(func(k, v []byte) bool {
		sb.WriteString(string(k))
		sb.WriteString("=")
		if len(v) > 16 {
			sb.Write(v[:16])
			sb.WriteString("…")
		} else {
			sb.Write(v)
		}
		sb.WriteString(" ")
		return true
	})
	return sb.String()
}

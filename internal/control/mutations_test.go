package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 的回归：模板落盘路径必须收口。
//
// `block_page.file` 是控制台能改的字段，而它决定"往哪个路径写文件" ——
// 不收口就等于"一个会话 + 一个字段 = 在服务器任意位置写文件"。
//
// **只测纯校验函数，不真写系统路径**：早先这组用例拿 `/etc/passwd`、`/tmp/x.html`
// 去调"写文件"，在 Windows 上真的写出了 `C:\etc\passwd` 与 `C:\tmp\x.html`
// （修复前的实现允许），在 Linux 上更是会碰到真实的 /etc —— 测试自己成了事故源。
func TestValidateTemplatePathRejectsEscapes(t *testing.T) {
	bad := []string{
		"", "   ",
		"/etc/passwd",
		"/tmp/x.html",
		`\windows\system32\evil.html`,
		"C:/windows/evil.html",
		"C:evil.html", // 盘符相对
		"..",
		"../outside.html",
		"../../outside.html",
		"sub/../../outside.html",
		`sub\..\..\outside.html`,
	}
	for _, name := range bad {
		if got, err := validateTemplatePath(name); err == nil {
			t.Errorf("%q 应当被拒绝，实际放行成 %q", name, got)
		}
	}

	// 正常用法不能被误伤
	good := []string{
		"block.html",
		"templates/block.html",
		"templates/nested/block.html",
		"templates\\block.html",
		"a.b.c.html",
	}
	for _, name := range good {
		if _, err := validateTemplatePath(name); err != nil {
			t.Errorf("%q 是正常相对路径，不该被拒：%v", name, err)
		}
	}
}

// 落盘：相对路径能写、临时文件不残留、内容正确。
//
// 全部在 t.TempDir() 里做，**绝不碰系统路径**。
func TestWriteTemplateFileWritesOnlyRelative(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()

	// 相对路径：写成功，内容正确，无 .tmp 残留
	good := filepath.Join("templates", "block.html")
	if err := writeTemplateFile(good, "<html>ok</html>"); err != nil {
		t.Fatalf("相对路径应当可用：%v", err)
	}
	b, err := os.ReadFile(good)
	if err != nil {
		t.Fatalf("写入的文件读不到：%v", err)
	}
	if !strings.Contains(string(b), "ok") {
		t.Errorf("写入内容不对：%q", b)
	}
	if _, err := os.Stat(good + ".tmp"); err == nil {
		t.Error("临时文件应当已经改名，不该留下 .tmp")
	}

	// 逃逸路径：必须在**写之前**就被拒（目录不该被创建出来）
	for _, bad := range []string{"../escape.html", "sub/../../escape.html", "/abs-escape.html"} {
		if err := writeTemplateFile(bad, "x"); err == nil {
			t.Errorf("%q 不该写成功", bad)
		}
	}
	// 确认没有在 tempDir 之外留下东西
	if _, err := os.Stat(filepath.Join(dir, "..", "escape.html")); err == nil {
		t.Error("逃逸文件被写到了上级目录")
	}
	if _, err := os.Stat(filepath.Join(dir, "sub", "..", "..", "escape.html")); err == nil {
		t.Error("逃逸文件被写到了上级目录")
	}
}

// SetEngine 变更的校验：非法模式/阈值要拒绝，切到会拦截的模式要给警告。
func TestSetEngineValidation(t *testing.T) {
	cur := &State{Engine: EngineState{Mode: "detect", InboundThreshold: 5}}

	bad := "yolo"
	if _, _, err := (SetEngine{Mode: &bad}).Apply(cur); err == nil {
		t.Error("非法 mode 应当被拒绝")
	}
	zero := 0
	if _, _, err := (SetEngine{InboundThreshold: &zero}).Apply(cur); err == nil {
		t.Error("阈值 0 应当被拒绝")
	}

	block := "block"
	next, warns, err := (SetEngine{Mode: &block}).Apply(cur)
	if err != nil {
		t.Fatalf("切到 block 不该失败：%v", err)
	}
	if next.Engine.Mode != "block" {
		t.Errorf("模式没改成 block：%q", next.Engine.Mode)
	}
	if cur.Engine.Mode != "detect" {
		t.Error("Apply 必须是纯函数，不能改到传入的 cur")
	}
	if len(warns) == 0 {
		t.Error("切到会拦截的模式应当给警告（这是'立刻开始 403'的语义变化）")
	}
}

// 热参数进 State 后必须完整：否则控制面推给引擎的是空值。
func TestEngineStateRoundTrip(t *testing.T) {
	st := &State{Engine: EngineState{Mode: "detect", InboundThreshold: 5}}
	block := "block"
	th := 3
	ban := true
	next, _, err := (SetEngine{
		Mode: &block, InboundThreshold: &th, BanOnBlock: &ban,
		CategoryThresholds: map[string]int{"xss": 7},
	}).Apply(st)
	if err != nil {
		t.Fatal(err)
	}
	if next.Engine.Mode != "block" || next.Engine.InboundThreshold != 3 ||
		!next.Engine.BanOnBlock || next.Engine.CategoryThresholds["xss"] != 7 {
		t.Fatalf("EngineState 没有完整带上：%+v", next.Engine)
	}
}

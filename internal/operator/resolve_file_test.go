package operator

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// 名单文件必须锁在规则目录内。
//
// 这条测试对应一个真实漏洞链：绝对路径曾被原样放行，而名单解析失败时的
// 错误里会带回文件内容，最后被规则校验接口回显 —— 认证之后的任意文件读。
func TestResolveFileConfinesToBase(t *testing.T) {
	base := t.TempDir()
	inside := filepath.Join(base, "allow.txt")
	if err := os.WriteFile(inside, []byte("10.0.0.0/8\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(base, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	ok := []string{"allow.txt", "./allow.txt", filepath.Join("sub", "..", "allow.txt"), inside}
	for _, name := range ok {
		if _, err := resolveFile(base, name); err != nil {
			t.Fatalf("目录内的 %q 应该通过，实得错误：%v", name, err)
		}
	}

	// 目录外的路径：曾经被原样放行的是**绝对路径**这一类。
	// 注意 Windows 的 filepath.IsAbs("/etc/passwd") 是 false（要有盘符才算绝对），
	// 所以这里用跨平台的绝对路径断言；Unix 上再补两条经典目标。
	outsideAbs, err := filepath.Abs(filepath.Join(base, "..", "outside.txt"))
	if err != nil {
		t.Fatal(err)
	}
	bad := []string{
		outsideAbs,
		"../outside.txt",
		"sub/../../outside.txt",
		filepath.Join(base, "..", "outside.txt"),
	}
	if runtime.GOOS != "windows" {
		bad = append(bad, "/etc/passwd", "/etc/hostname")
	}
	for _, name := range bad {
		if _, err := resolveFile(base, name); err == nil {
			t.Fatalf("越界的 %q 必须被拒绝", name)
		}
	}
}

// 名单解析的错误里不能出现原始行内容。
func TestBuildIPMatchErrorHidesLine(t *testing.T) {
	_, err := buildIPMatch([]string{"root:x:0:0:root:/root:/bin/bash"})
	if err == nil {
		t.Fatal("非法行必须报错")
	}
	msg := err.Error()
	if strings.Contains(msg, "root:x") || strings.Contains(msg, "/bin/bash") {
		t.Fatalf("错误信息回显了文件内容：%s", msg)
	}
	if !strings.Contains(msg, "第 1 行") {
		t.Fatalf("错误信息应指出行号：%s", msg)
	}
}

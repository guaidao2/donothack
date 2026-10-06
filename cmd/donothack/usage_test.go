package main

import (
	"strings"
	"testing"
)

// TestUsageListsEverySubcommandAndFlag 守"帮助必须写全"。
//
// 起因：`hash-password` 加进代码之后，帮助里其实写了，但 `donothack -h`
// 走的是 flag 包默认输出 —— 只列参数、不列子命令，头部还打印本机绝对路径；
// 而 `donothack help` 反过来只列子命令、不列参数。两个入口各缺一半，
// 用户按最自然的 `-h` 敲下去看到的恰好是最不像样的那份。
//
// 所以这里钉住两件事：一份帮助里子命令与参数都要有；且不能出现本机路径。
func TestUsageListsEverySubcommandAndFlag(t *testing.T) {
	var sb strings.Builder
	writeUsage(&sb)
	out := sb.String()

	must := []string{
		// 子命令
		"rules check", "rules test", "hash-password", "version", "help",
		// 参数
		"-c ", "-check-config", "-print-budget", "-no-rules", "-h, --help",
	}
	for _, want := range must {
		if !strings.Contains(out, want) {
			t.Errorf("帮助里缺少 %q", want)
		}
	}

	// 帮助里不该出现本机绝对路径（flag 包默认输出是 "Usage of <exe 路径>"）。
	for _, bad := range []string{"Usage of", ":\\", "C:/", "/home/", "/Users/"} {
		if strings.Contains(out, bad) {
			t.Errorf("帮助里出现了本机路径痕迹 %q", bad)
		}
	}
}

// TestHashPasswordHelpNeedsNoStdin 守 `hash-password -h` 不会去读标准输入。
//
// 改之前它把 -h 当空气，直接等口令；在终端里敲 `hash-password -h` 的人
// 会看到一个"口令："提示，然后只能 Ctrl-C。
func TestHashPasswordHelpNeedsNoStdin(t *testing.T) {
	for _, arg := range []string{"-h", "--help", "help"} {
		if code := runHashPasswordCmd([]string{arg}); code != 0 {
			t.Errorf("hash-password %s 应返回 0，实际 %d", arg, code)
		}
	}
	// 传别的参数要明确拒绝，而不是悄悄忽略。
	if code := runHashPasswordCmd([]string{"我的口令"}); code != 2 {
		t.Errorf("hash-password 传口令参数应返回 2（拒绝），实际 %d", code)
	}
}

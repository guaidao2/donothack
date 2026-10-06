package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// 审计发现 L-1 的回归：`total_max_mb` 必须是**目录级**配额。
//
// 修复前的口径有两个缺口，叠加成 2.5 倍：
//  1. 配额是"每族"的（access / app 各一份），N 条日志 → 上限 ≈ N × 配额；
//  2. **正在写的那个文件不参与统计**，于是每条还能多出 max_size。
//
// 实测（各写 40 KiB、配额 32 KiB）：目录总占用 81920 字节 = 配置值的 2.50 倍。
// 20 GB 的盘按 total_max_mb: 512 规划容量，实际能写出 1 GB+。
func TestDirBudgetCapsWholeDirectory(t *testing.T) {
	dir := t.TempDir()
	const (
		maxSize  = 8 << 10  // 单文件 8 KiB
		totalMax = 32 << 10 // 目录总配额 32 KiB
	)

	mk := func(name string) *rotateWriter {
		w, err := newRotateWriter(rotateOptions{
			Path:       filepath.Join(dir, name),
			MaxSize:    maxSize,
			MaxBackups: 100, // 份数放宽，让"总配额"这条线单独起作用
			TotalMax:   totalMax,
		})
		if err != nil {
			t.Fatalf("创建 %s 失败：%v", name, err)
		}
		return w
	}

	access := mk("access.jsonl")
	app := mk("app.log")
	defer func() { _ = access.Close() }()
	defer func() { _ = app.Close() }()

	// 各写 40 KiB（远超 32 KiB 的目录配额）
	blob := make([]byte, 4096)
	for i := range blob {
		blob[i] = 'x'
	}
	for i := 0; i < 10; i++ {
		if _, err := access.Write(blob); err != nil {
			t.Fatal(err)
		}
		if _, err := app.Write(blob); err != nil {
			t.Fatal(err)
		}
	}
	// 触发一次清理（轮转与清理都在写路径上做）
	if _, err := access.cleanup(); err != nil {
		t.Fatal(err)
	}

	// 统计**整个目录**（含正在写的文件）——这正是修复后的口径
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		st, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		total += st.Size()
		names = append(names, e.Name())
	}

	t.Logf("目录内文件：%v，总占用 %d 字节（配额 %d）", names, total, totalMax)
	if total > totalMax {
		t.Fatalf("目录总占用 %d 超过配额 %d（%.2f 倍）—— 配额没有覆盖整个目录",
			total, totalMax, float64(total)/float64(totalMax))
	}
}

// 正在写的文件不能被删除（句柄还开着，删了后续写入会失败）。
func TestDirBudgetNeverDeletesActiveFile(t *testing.T) {
	dir := t.TempDir()
	w, err := newRotateWriter(rotateOptions{
		Path:       filepath.Join(dir, "access.jsonl"),
		MaxSize:    4 << 10,
		MaxBackups: 100,
		TotalMax:   8 << 10, // 故意比正在写的文件还小
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()

	blob := make([]byte, 1024)
	for i := 0; i < 20; i++ {
		if _, err := w.Write(blob); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "access.jsonl")); err != nil {
		t.Fatalf("正在写的文件被删了：%v", err)
	}
	// 还能继续写（句柄有效）
	if _, err := w.Write(blob); err != nil {
		t.Fatalf("清理之后写入失败了：%v", err)
	}
}

// Close 之后要把自己从目录预算里摘掉，否则长跑进程会攒下无效条目。
func TestDirBudgetUnregistersOnClose(t *testing.T) {
	dir := t.TempDir()
	w, err := newRotateWriter(rotateOptions{
		Path:     filepath.Join(dir, "a.log"),
		MaxSize:  1 << 20,
		TotalMax: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	b := w.budget
	if b == nil {
		t.Fatal("应当注册进目录预算")
	}
	b.mu.Lock()
	n := len(b.writers)
	b.mu.Unlock()
	if n != 1 {
		t.Fatalf("注册数应为 1，实际 %d", n)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	n = len(b.writers)
	b.mu.Unlock()
	if n != 0 {
		t.Fatalf("Close 之后应当摘掉注册，实际还剩 %d", n)
	}
}

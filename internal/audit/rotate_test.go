package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tmpDir 在仓库内的 .tmp/test 下建目录。
//
// 刻意不用 t.TempDir()：那会落到系统临时目录，而本项目的纪律是
// "所有文件操作必须留在工作目录内"（见 AGENTS.md §1）。
func tmpDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join("..", "..", ".tmp", "test", "audit", name)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("清理测试目录失败：%v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建测试目录失败：%v", err)
	}
	return dir
}

func listLogs(t *testing.T, dir, base string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录失败：%v", err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), base) {
			names = append(names, e.Name())
		}
	}
	return names
}

func writeN(t *testing.T, w *rotateWriter, n int, line string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("第 %d 次写入失败：%v", i, err)
		}
	}
}

// 单文件超过上限要轮转，且轮转份数受 max_backups 限制。
func TestRotationRespectsMaxBackups(t *testing.T) {
	dir := tmpDir(t, "maxbackups")
	path := filepath.Join(dir, "donothack.jsonl")

	w, err := newRotateWriter(rotateOptions{
		Path:       path,
		MaxSize:    256, // 每行 64 字节 → 4 行就轮转一次
		MaxBackups: 2,
	})
	if err != nil {
		t.Fatalf("构造失败：%v", err)
	}
	defer w.Close()

	line := strings.Repeat("x", 63) + "\n" // 64 字节
	writeN(t, w, 40, line)                 // 约 10 次轮转

	rotated := 0
	for _, n := range listLogs(t, dir, "donothack") {
		if n != "donothack.jsonl" {
			rotated++
		}
	}
	if rotated > 2 {
		t.Errorf("轮转文件 %d 份，超过 max_backups=2；目录内容：%v", rotated, listLogs(t, dir, "donothack"))
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("当前日志文件必须存在：%v", err)
	}
	if _, _, _, deleted := w.Stats(); deleted == 0 {
		t.Error("发生过轮转却没有删除任何旧文件，说明保留策略没生效")
	}
}

// 总配额是硬顶：即使份数没超，目录体积也必须被压到配额以内。
func TestRotationEnforcesTotalBudget(t *testing.T) {
	dir := tmpDir(t, "totalbudget")
	path := filepath.Join(dir, "donothack.jsonl")

	const totalMax = 1024
	const maxSize = 512
	w, err := newRotateWriter(rotateOptions{
		Path:       path,
		MaxSize:    maxSize,
		MaxBackups: 100, // 份数放宽，逼总配额生效
		TotalMax:   totalMax,
	})
	if err != nil {
		t.Fatalf("构造失败：%v", err)
	}
	defer w.Close()

	writeN(t, w, 200, strings.Repeat("y", 63)+"\n")

	var total int64
	for _, n := range listLogs(t, dir, "donothack") {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		total += st.Size()
	}
	// 允许一个文件的余量（当前文件在轮转前可能已接近 maxSize）。
	if total > totalMax+maxSize {
		t.Errorf("日志目录 %d 字节，超过总配额 %d（余量 %d）", total, totalMax, maxSize)
	}
}

// 磁盘水位低于阈值时必须丢弃写入，而且不能报错、不能阻塞。
func TestDiskWatermarkDropsWrites(t *testing.T) {
	dir := tmpDir(t, "watermark")
	path := filepath.Join(dir, "donothack.jsonl")

	w, err := newRotateWriter(rotateOptions{
		Path:    path,
		MaxSize: 1 << 20,
		// 水位设成 1 PiB：任何真实磁盘都不可能满足，等价于"必定触发丢弃"
		MinFree: 1 << 50,
	})
	if err != nil {
		t.Fatalf("构造失败：%v", err)
	}
	defer w.Close()

	n, err := w.Write([]byte("should be dropped\n"))
	if err != nil {
		t.Fatalf("磁盘水位不足时不应报错（否则会拖累请求路径）：%v", err)
	}
	if n != len("should be dropped\n") {
		t.Errorf("应当假装写成功，返回 %d", n)
	}
	if dropped, _, _, _ := w.Stats(); dropped != 1 {
		t.Errorf("丢弃计数 = %d，期望 1", dropped)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("当前文件应存在：%v", err)
	}
	if st.Size() != 0 {
		t.Errorf("水位不足时不应写入任何内容，实际 %d 字节", st.Size())
	}
}

// 启动时就要清理历史文件：只靠"轮转时清理"的话，长期不轮转的进程会一直堆垃圾。
func TestStartupCleanup(t *testing.T) {
	dir := tmpDir(t, "startup")
	path := filepath.Join(dir, "donothack.jsonl")

	// 预置 20 个"历史"文件
	for i := 0; i < 20; i++ {
		p := filepath.Join(dir, fmt.Sprintf("donothack-20260101-0000%02d.jsonl", i))
		if err := os.WriteFile(p, []byte(strings.Repeat("z", 100)), 0o644); err != nil {
			t.Fatalf("预置文件失败：%v", err)
		}
	}
	// 让 mtime 有序，便于断言"删最旧"
	old := time.Now().Add(-24 * time.Hour)
	for i := 0; i < 20; i++ {
		p := filepath.Join(dir, fmt.Sprintf("donothack-20260101-0000%02d.jsonl", i))
		_ = os.Chtimes(p, old.Add(time.Duration(i)*time.Minute), old.Add(time.Duration(i)*time.Minute))
	}

	w, err := newRotateWriter(rotateOptions{
		Path:       path,
		MaxSize:    1 << 20,
		MaxBackups: 3,
	})
	if err != nil {
		t.Fatalf("构造失败：%v", err)
	}
	defer w.Close()

	remaining := 0
	for _, n := range listLogs(t, dir, "donothack") {
		if n != "donothack.jsonl" {
			remaining++
		}
	}
	if remaining != 3 {
		t.Errorf("启动清理后应剩 3 份，实际 %d 份：%v", remaining, listLogs(t, dir, "donothack"))
	}
}

// 轮转后压缩旧文件，省磁盘。
func TestRotationCompresses(t *testing.T) {
	dir := tmpDir(t, "compress")
	path := filepath.Join(dir, "donothack.jsonl")

	w, err := newRotateWriter(rotateOptions{
		Path:       path,
		MaxSize:    256,
		MaxBackups: 5,
		Compress:   true,
	})
	if err != nil {
		t.Fatalf("构造失败：%v", err)
	}
	writeN(t, w, 20, strings.Repeat("c", 63)+"\n")
	// 关闭会等压缩收尾
	if err := w.Close(); err != nil {
		t.Fatalf("关闭失败：%v", err)
	}

	gz := 0
	for _, n := range listLogs(t, dir, "donothack") {
		if strings.HasSuffix(n, ".gz") {
			gz++
		}
	}
	if gz == 0 {
		t.Errorf("开启压缩后应当出现 .gz 文件：%v", listLogs(t, dir, "donothack"))
	}
}

// 访问日志策略：hit 只记非 pass，sample 保留全部非 pass。
func TestAccessModeHitAndSample(t *testing.T) {
	run := func(mode string, ratio int, verdicts []string) (written, skipped int64) {
		lg, err := New(Options{
			Level: "error", Format: "json",
			Writer:            &discard{},
			AppWriter:         &discard{},
			AccessMode:        mode,
			AccessSampleRatio: ratio,
		})
		if err != nil {
			t.Fatalf("构造日志器失败：%v", err)
		}
		defer lg.Close()
		for _, v := range verdicts {
			lg.Access(AccessRecord{TxID: "t", Verdict: v, URI: "/x"})
		}
		st := lg.Stats()
		return st.AccessWritten, st.AccessSkipped
	}

	verdicts := []string{"pass", "pass", "block", "pass", "bad_gateway"}

	written, skipped := run("all", 100, verdicts)
	if written != 5 || skipped != 0 {
		t.Errorf("all 模式应全记：written=%d skipped=%d", written, skipped)
	}

	written, skipped = run("hit", 100, verdicts)
	if written != 2 || skipped != 3 {
		t.Errorf("hit 模式应只记 2 条非 pass：written=%d skipped=%d", written, skipped)
	}

	// sample：3 条 pass 里按 1/100 采样（只会命中第 1 条），2 条非 pass 全记 → 3 条
	written, skipped = run("sample", 100, verdicts)
	if written != 3 || skipped != 2 {
		t.Errorf("sample 模式应记 1 条采样 + 2 条非 pass：written=%d skipped=%d", written, skipped)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// 轮转文件名必须唯一：同一秒内多次轮转不能互相覆盖。
func TestUniquePath(t *testing.T) {
	dir := tmpDir(t, "unique")
	p := filepath.Join(dir, "a.jsonl")
	if got := uniquePath(p); got != p {
		t.Errorf("文件不存在时应原样返回，得到 %q", got)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := uniquePath(p)
	if got == p {
		t.Error("文件已存在时必须换一个名字，否则会覆盖已有日志")
	}
}

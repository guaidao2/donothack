package audit

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// rotateOptions 是轮转与保留策略。
//
// 三条上限各管一件事，缺一不可：
//   - MaxSize：单文件多大就轮转（防止一个文件无限涨）
//   - MaxBackups：最多留几份（防止份数无限涨）
//   - TotalMax：日志目录**总配额**（防止份数×大小相乘后仍然失控）
//
// 再加上 MinFree 这道磁盘水位：低于它就停止写日志。
// **日志的价值远低于业务可用性** —— 磁盘被日志写满会连带拖死业务与系统服务，
// 所以这里宁可丢日志，也绝不把盘写满。
type rotateOptions struct {
	Path       string // 当前文件路径（含文件名）
	MaxSize    int64  // 单文件上限（字节），<=0 表示不轮转
	MaxBackups int    // 保留的轮转份数
	TotalMax   int64  // 日志目录总配额（字节），0 表示不限
	MinFree    int64  // 磁盘剩余水位（字节），0 表示不检查
	Compress   bool   // 轮转后 gzip
}

// rotateWriter 是一个会自我轮转、自我清理的 io.Writer。
//
// 并发：外层 lockedWriter 已保证串行；这里再用自己的 mu 保护文件状态，
// 因为单元测试会直接用它、不经过 Logger。
// 锁序固定为 lockedWriter -> rotateWriter.mu，不存在反向获取。
type rotateWriter struct {
	o rotateOptions

	dir     string
	base    string // 不含扩展名，例如 donothack
	ext     string // 含点，例如 .jsonl
	pattern string // 轮转文件的 glob，例如 donothack-*.jsonl*

	mu     sync.Mutex
	f      *os.File
	size   int64
	closed bool

	// 统计：这些数要进指标，否则"日志被丢了"没人知道
	dropped         atomic.Int64 // 因磁盘水位被丢弃的写入次数
	rotations       atomic.Int64
	skippedCompress atomic.Int64
	deletedFiles    atomic.Int64

	// 磁盘剩余空间缓存，避免每次写都做一次 statfs
	freeMu sync.Mutex
	freeAt time.Time
	freeB  int64

	// 异步压缩队列（长度 1）：压不过来就跳过压缩，绝不阻塞写。
	gzq  chan string
	gzwg sync.WaitGroup

	// budget 是本目录的共享配额（同一目录下多条日志共用一份）。
	budget *dirBudget

	now func() time.Time
}

const freeProbeTTL = 5 * time.Second

// newRotateWriter 打开日志文件，并在启动时先做一次清理。
//
// 启动时清理很重要：只靠"轮转时清理"的话，一个长期运行的进程如果一直没到轮转阈值，
// 目录里旧的垃圾就永远不会被清掉。
func newRotateWriter(o rotateOptions) (*rotateWriter, error) {
	if strings.TrimSpace(o.Path) == "" {
		return nil, fmt.Errorf("日志路径为空")
	}
	ext := filepath.Ext(o.Path)
	base := strings.TrimSuffix(filepath.Base(o.Path), ext)
	dir := filepath.Dir(o.Path)
	if dir == "" {
		dir = "."
	}
	if ext == "" {
		ext = ".log"
	}

	w := &rotateWriter{
		o:       o,
		dir:     dir,
		base:    base,
		ext:     ext,
		pattern: filepath.Join(dir, base+"-*"+ext+"*"),
		now:     time.Now,
	}
	// 注册进**目录级**共享预算：配额是"每目录"的，不是"每条日志"的（审计发现 L-1）。
	// 必须在下面"启动即清理"之前注册，否则第一次 enforce 看不到自己、
	// 也看不到同目录的其它日志，等于没配额。
	w.budget = budgetFor(dir, o.TotalMax)
	w.budget.register(w)

	f, err := os.OpenFile(o.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		w.budget.unregister(w)
		return nil, fmt.Errorf("打开日志文件 %s 失败：%w", o.Path, err)
	}
	w.f = f
	if st, err := f.Stat(); err == nil {
		w.size = st.Size()
	}

	// 启动即清理一次历史文件。
	if _, err := w.cleanup(); err != nil {
		// 清理失败不该阻止启动，但要让调用方知道。
		fmt.Fprintf(os.Stderr, "donothack: 清理旧日志失败：%v\n", err)
	}

	if o.Compress {
		w.gzq = make(chan string, 1)
		w.gzwg.Add(1)
		go w.gzipWorker()
	}
	return w, nil
}

func (w *rotateWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// 磁盘水位检查：低于水位就丢弃这一条，假装写成功（调用方不该因此报错或重试）。
	if !w.diskOK() {
		w.dropped.Add(1)
		return len(p), nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, os.ErrClosed
	}
	if w.o.MaxSize > 0 && w.size > 0 && w.size+int64(len(p)) > w.o.MaxSize {
		if err := w.rotateLocked(); err != nil {
			// 轮转失败不阻断写入：继续写当前文件，至少日志没丢。
			fmt.Fprintf(os.Stderr, "donothack: 日志轮转失败：%v\n", err)
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	if err != nil {
		return n, err
	}
	return n, nil
}

// rotateLocked 把当前文件改名归档，再开一个新文件，然后执行保留策略。
func (w *rotateWriter) rotateLocked() error {
	if w.f != nil {
		if err := w.f.Close(); err != nil {
			return fmt.Errorf("关闭当前日志失败：%w", err)
		}
	}

	archived := filepath.Join(w.dir, fmt.Sprintf("%s-%s%s", w.base, w.now().Format("20060102-150405"), w.ext))
	archived = uniquePath(archived)

	if err := os.Rename(w.o.Path, archived); err != nil {
		// 改名失败：重新打开原文件继续写，不让日志中断。
		f, reopenErr := os.OpenFile(w.o.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if reopenErr != nil {
			return fmt.Errorf("重命名失败(%v) 且无法重新打开 %s：%w", err, w.o.Path, reopenErr)
		}
		w.f = f
		if st, statErr := f.Stat(); statErr == nil {
			w.size = st.Size()
		}
		return fmt.Errorf("归档日志失败：%w", err)
	}

	f, err := os.OpenFile(w.o.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("轮转后无法打开新日志 %s：%w", w.o.Path, err)
	}
	w.f = f
	w.size = 0
	w.rotations.Add(1)

	if w.gzq != nil {
		select {
		case w.gzq <- archived:
		default:
			// 压缩队列满：放弃压缩这一份，不阻塞写日志。
			w.skippedCompress.Add(1)
		}
	}

	if _, err := w.cleanup(); err != nil {
		return err
	}
	return nil
}

// cleanup 按"份数"和"总配额"两条线删最旧的轮转文件。
//
// 当前正在写的文件永不删除。
func (w *rotateWriter) cleanup() ([]string, error) {
	files, err := filepath.Glob(w.pattern)
	if err != nil {
		return nil, err
	}

	type entry struct {
		path string
		size int64
		mod  time.Time
	}
	var entries []entry
	var total int64
	for _, p := range files {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			continue
		}
		entries = append(entries, entry{path: p, size: st.Size(), mod: st.ModTime()})
		total += st.Size()
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].mod.Before(entries[j].mod) })

	var deleted []string
	remove := func(e entry) {
		if err := os.Remove(e.path); err != nil {
			return
		}
		deleted = append(deleted, filepath.Base(e.path))
		total -= e.size
		w.deletedFiles.Add(1)
	}

	// 1) 份数上限
	if w.o.MaxBackups >= 0 && len(entries) > w.o.MaxBackups {
		for i := 0; i < len(entries)-w.o.MaxBackups; i++ {
			remove(entries[i])
		}
		entries = entries[len(entries)-min(len(entries), w.o.MaxBackups):]
	}

	// 2) **目录总配额**（份数×大小相乘之后仍然可能失控）。
	//
	// 这一步走目录级共享预算（审计发现 L-1）：原先只统计自己这一族的归档文件、
	// 还不含正在写的那个，于是同一目录两条日志的实际上限是 2 × 配额，
	// 实测能到配置值的 2.5 倍。现在按目录汇总（含正在写的）再删最旧的。
	if w.budget != nil {
		deleted = append(deleted, w.budget.enforce()...)
	}
	return deleted, nil
}

// diskOK 检查磁盘剩余是否还在水位之上，结果缓存 5 秒。
func (w *rotateWriter) diskOK() bool {
	if w.o.MinFree <= 0 {
		return true
	}
	w.freeMu.Lock()
	defer w.freeMu.Unlock()
	if time.Since(w.freeAt) < freeProbeTTL {
		return w.freeB >= w.o.MinFree
	}
	free, err := diskFree(w.dir)
	if err != nil {
		// 查不到剩余空间时不要因此丢日志：放行并让下次再试。
		w.freeAt = time.Now()
		w.freeB = w.o.MinFree
		return true
	}
	w.freeAt = time.Now()
	w.freeB = free
	return free >= w.o.MinFree
}

func (w *rotateWriter) gzipWorker() {
	defer w.gzwg.Done()
	for path := range w.gzq {
		err := gzipFile(path)
		if err == nil {
			continue
		}
		if os.IsNotExist(err) {
			// 文件在排队期间已被保留策略删掉了（说明配额正在起作用），
			// 这不是"压缩失败"，不该计进指标，否则这个数会被噪声淹没。
			continue
		}
		w.skippedCompress.Add(1)
	}
}

// gzipFile 压缩并删除原文件。失败时保留原文件（宁可占空间，不要丢日志）。
func gzipFile(path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()

	dst := path + ".gz"
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		_ = zw.Close()
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return os.Remove(path)
}

func (w *rotateWriter) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	f := w.f
	w.mu.Unlock()

	// 从目录预算里摘掉自己：不摘的话长跑进程里会攒下指向已关闭写入器的条目，
	// enforce 会去 glob 一个已经没人写的模式。**必须在 Close 里做**，
	// 因为"同一目录下的日志"这个集合是动态的（测试与热重载都会开关日志）。
	if w.budget != nil {
		w.budget.unregister(w)
	}

	if w.gzq != nil {
		close(w.gzq)
		w.gzwg.Wait()
	}
	if f != nil {
		return f.Close()
	}
	return nil
}

// Stats 返回轮转统计，供指标与 /readyz 使用。
func (w *rotateWriter) Stats() (dropped, rotations, skippedCompress, deletedFiles int64) {
	return w.dropped.Load(), w.rotations.Load(), w.skippedCompress.Load(), w.deletedFiles.Load()
}

// uniquePath 避免同一秒内多次轮转时文件名撞车。
func uniquePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	for i := 1; i < 1000; i++ {
		candidate := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return fmt.Sprintf("%s.%d", path, time.Now().UnixNano())
}

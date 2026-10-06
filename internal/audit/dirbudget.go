package audit

import (
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// dirBudget 是**按目录共享**的日志配额。
//
// 为什么不是"每条日志一个配额"（审计发现 L-1）：配置与文档（`config.example.yaml`、
// ）都写的是"目录总配额、硬顶、优先于份数"，而实现是每条 file 日志
// 各拿一份 —— 同一目录里 access + app 两条日志，实际上限就是 2 × 配额；
// 而且各自**正在写的那个文件**还不计入统计。实测（各写 40 KiB、配额 32 KiB）
// 目录总占用 81920 字节 = 配置值的 **2.50 倍**。
//
// 代价是真实的：20 GB 的盘按 `total_max_mb: 512` 规划容量，实际能写出 1 GB+。
// 所以这里改成按目录汇总（**包含正在写的文件**）再删最旧的。
//
// 正在写的文件不会被删（句柄还开着），它们的总量天然被每条的 `MaxSize` 限住；
// 如果删完所有可删文件仍然超配额，就到此为止并如实计数。
type dirBudget struct {
	mu       sync.Mutex
	dir      string
	totalMax int64
	writers  map[*rotateWriter]struct{}
}

var (
	dirBudgetsMu sync.Mutex
	dirBudgets   = map[string]*dirBudget{}
)

// budgetFor 取出（或建立）某个目录的共享预算。
//
// totalMax 取该目录下所有写入器里的**最大值**：`total_max_mb` 是全局配置项，
// 同一目录下各条日志拿到的是同一个值；万一不一致，取大的那个更保守
// （配额宽松一点总比"配额被静默收紧、日志丢得莫名其妙"好排查）。
func budgetFor(dir string, totalMax int64) *dirBudget {
	dirBudgetsMu.Lock()
	defer dirBudgetsMu.Unlock()
	b, ok := dirBudgets[dir]
	if !ok {
		b = &dirBudget{dir: dir, totalMax: totalMax, writers: map[*rotateWriter]struct{}{}}
		dirBudgets[dir] = b
		return b
	}
	if totalMax > b.totalMax {
		b.totalMax = totalMax
	}
	return b
}

func (b *dirBudget) register(w *rotateWriter) {
	b.mu.Lock()
	b.writers[w] = struct{}{}
	b.mu.Unlock()
}

func (b *dirBudget) unregister(w *rotateWriter) {
	b.mu.Lock()
	delete(b.writers, w)
	empty := len(b.writers) == 0
	b.mu.Unlock()
	if empty {
		// 目录里没有写入器了就把它从注册表摘掉：否则长跑的进程会攒下一堆空条目。
		dirBudgetsMu.Lock()
		if cur, ok := dirBudgets[b.dir]; ok && cur == b {
			b.mu.Lock()
			stillEmpty := len(b.writers) == 0
			b.mu.Unlock()
			if stillEmpty {
				delete(dirBudgets, b.dir)
			}
		}
		dirBudgetsMu.Unlock()
	}
}

// enforce 把**整个目录**压到总配额之下，返回被删掉的文件名。
//
// 计入口径（这是修复的关键）：同一目录下**所有**已注册写入器的
// 轮转文件 + 各自正在写的文件。
func (b *dirBudget) enforce() []string {
	if b == nil || b.totalMax <= 0 {
		return nil
	}

	b.mu.Lock()
	writers := make([]*rotateWriter, 0, len(b.writers))
	for w := range b.writers {
		writers = append(writers, w)
	}
	totalMax := b.totalMax
	b.mu.Unlock()

	type entry struct {
		path   string
		size   int64
		mod    time.Time
		active bool
		owner  *rotateWriter
	}
	seen := map[string]bool{}
	var entries []entry
	var total int64

	add := func(path string, owner *rotateWriter, active bool) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		st, err := os.Stat(path)
		if err != nil || st.IsDir() {
			return
		}
		entries = append(entries, entry{path: path, size: st.Size(), mod: st.ModTime(),
			active: active, owner: owner})
		total += st.Size()
	}

	for _, w := range writers {
		files, err := filepath.Glob(w.pattern)
		if err == nil {
			for _, p := range files {
				add(p, w, false)
			}
		}
		// **正在写的文件也要计入**：原先它被排除在统计之外，
		// 于是每条日志的实际占用是"配额 + max_size"。
		add(w.o.Path, w, true)
	}

	// 从最旧开始删，但**不删正在写的**
	sort.Slice(entries, func(i, j int) bool { return entries[i].mod.Before(entries[j].mod) })
	var deleted []string
	for _, e := range entries {
		if total <= totalMax {
			break
		}
		if e.active {
			continue // 句柄还开着，删了会让后续写入失败
		}
		if err := os.Remove(e.path); err != nil {
			continue
		}
		total -= e.size
		deleted = append(deleted, filepath.Base(e.path))
		if e.owner != nil {
			e.owner.deletedFiles.Add(1)
		}
	}
	return deleted
}

// dirTotal 返回该目录下已注册日志的当前总占用（给指标与测试用）。
func (b *dirBudget) dirTotal() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	writers := make([]*rotateWriter, 0, len(b.writers))
	for w := range b.writers {
		writers = append(writers, w)
	}
	b.mu.Unlock()

	seen := map[string]bool{}
	var total int64
	addSize := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			total += st.Size()
		}
	}
	for _, w := range writers {
		if files, err := filepath.Glob(w.pattern); err == nil {
			for _, p := range files {
				addSize(p)
			}
		}
		addSize(w.o.Path)
	}
	return total
}

// Package profile 负责按运行环境探测资源档位，并把档位翻译成各项资源预算。
//
// 设计依据：
//
// 三条不变量：
//  1. 档位决定一切上限（检查体积、连接数、规则数、ring buffer、限速表容量）。
//  2. 每项资源都必须有上限 —— 无界即漏洞。
//  3. 探测不到时用保守默认值，并把探测来源打印出来，不靠人手填。
package profile

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
)

// Name 是档位名。
type Name string

const (
	Small  Name = "small"
	Medium Name = "medium"
	Large  Name = "large"
	// Auto 表示由 Detect 决定实际档位。
	Auto Name = "auto"
)

// Params 是一个档位的全部预算参数。
type Params struct {
	Name Name

	// MaxInspectBody 请求体检查上限（字节）。
	MaxInspectBody int64
	// MaxConns 最大并发连接数。
	MaxConns int
	// MaxIdleConnsPerHost 上游每主机空闲连接数。
	MaxIdleConnsPerHost int
	// MaxRules 规则集条数上限。
	MaxRules int
	// MaxPrefilterLiterals 预筛自动机字面量上限。
	MaxPrefilterLiterals int
	// RingBufferSize 内存中保留的命中事件条数。
	RingBufferSize int
	// RateLimitTableCapacity 限速/封禁状态表容量（必须有限，否则伪造源 IP 可打爆内存）。
	RateLimitTableCapacity int
	// ConsoleMemBudgetMiB 控制台额外内存预算。
	ConsoleMemBudgetMiB int
	// GOGC 传给 debug.SetGCPercent。
	GOGC int
	// MemLimitRatio 软内存上限占可用内存的比例（传给 debug.SetMemoryLimit）。
	MemLimitRatio float64
	// TargetRPS 该档位的吞吐目标（1 KiB GET，仅用于打印与门禁参考）。
	TargetRPS int
}

// 每连接的读缓冲、写缓冲与事务对象预算（字节）。见 。
const perConnBytes = 16 << 10

var table = map[Name]Params{
	Small: {
		Name:                   Small,
		MaxInspectBody:         128 << 10,
		MaxConns:               256,
		MaxIdleConnsPerHost:    16,
		MaxRules:               400,
		MaxPrefilterLiterals:   20000,
		RingBufferSize:         256,
		RateLimitTableCapacity: 8192,
		ConsoleMemBudgetMiB:    8,
		GOGC:                   200,
		MemLimitRatio:          0.50,
		TargetRPS:              3000,
	},
	Medium: {
		Name:                   Medium,
		MaxInspectBody:         512 << 10,
		MaxConns:               1024,
		MaxIdleConnsPerHost:    64,
		MaxRules:               2000,
		MaxPrefilterLiterals:   60000,
		RingBufferSize:         1024,
		RateLimitTableCapacity: 65536,
		ConsoleMemBudgetMiB:    24,
		GOGC:                   200,
		MemLimitRatio:          0.50,
		TargetRPS:              8000,
	},
	Large: {
		Name:                   Large,
		MaxInspectBody:         1 << 20,
		MaxConns:               4096,
		MaxIdleConnsPerHost:    256,
		MaxRules:               10000,
		MaxPrefilterLiterals:   200000,
		RingBufferSize:         4096,
		RateLimitTableCapacity: 262144,
		ConsoleMemBudgetMiB:    64,
		GOGC:                   100,
		MemLimitRatio:          0.70,
		TargetRPS:              20000,
	},
}

// Get 返回一个档位的参数。未知档位返回 Medium。
func Get(n Name) Params {
	if p, ok := table[n]; ok {
		return p
	}
	return table[Medium]
}

// Parse 解析配置里的档位字符串。
func Parse(s string) (Name, error) {
	switch Name(strings.ToLower(strings.TrimSpace(s))) {
	case Small:
		return Small, nil
	case Medium:
		return Medium, nil
	case Large:
		return Large, nil
	case Auto:
		return Auto, nil
	case "":
		return Auto, nil
	default:
		return "", fmt.Errorf("未知 profile %q（可选 small | medium | large | auto）", s)
	}
}

// Detection 记录探测结果与来源，来源要打印出来，方便排查"为什么是这个档位"。
type Detection struct {
	NumCPU     int
	CPUs       float64 // 由 cgroup quota 推出，0 表示未知
	CPUSource  string
	MemBytes   int64 // 0 表示未知
	MemSource  string
	Resolved   Name
	Resolution string
}

// Detect 按 cgroup v2 → cgroup v1 → /proc/meminfo 的顺序探测；
// 都拿不到时退化为"只看核数"，并如实标注来源为 unknown。
func Detect() Detection {
	d := Detection{NumCPU: runtime.NumCPU(), CPUSource: "runtime.NumCPU"}

	if cpus, src, ok := detectCgroupCPUs(); ok {
		d.CPUs = cpus
		d.CPUSource = src
	}

	if lim := os.Getenv("GOMEMLIMIT"); lim != "" {
		if n, err := parseByteSize(lim); err == nil && n > 0 {
			d.MemBytes = n
			d.MemSource = "env:GOMEMLIMIT"
		}
	}
	if d.MemBytes == 0 {
		if n, src, ok := detectMemoryLimit(); ok {
			d.MemBytes = n
			d.MemSource = src
		}
	}
	if d.MemSource == "" {
		d.MemSource = "unknown"
	}

	d.Resolved, d.Resolution = resolve(d)
	return d
}

// Resolve 在用户显式配置档位时尊重配置，否则用探测结果。
// configured 为 Auto 或空时按探测决定。
func (d Detection) Resolve(configured Name) (Name, string) {
	if configured != "" && configured != Auto {
		return configured, fmt.Sprintf("配置显式指定 %s", configured)
	}
	return d.Resolved, "自动探测：" + d.Resolution
}

// resolve 只按核数与内存决定档位，不做任何业务判断。
func resolve(d Detection) (Name, string) {
	cpus := float64(d.NumCPU)
	if d.CPUs > 0 {
		cpus = d.CPUs
	}

	if d.MemBytes == 0 {
		// 内存未知：只按核数选，且不选 large（保守）。
		switch {
		case cpus <= 1:
			return Small, fmt.Sprintf("%.0f 核、内存未知 → small（保守）", cpus)
		case cpus <= 2:
			return Medium, fmt.Sprintf("%.0f 核、内存未知 → medium（保守）", cpus)
		default:
			return Medium, fmt.Sprintf("%.0f 核、内存未知 → medium（内存未知时不选 large）", cpus)
		}
	}

	// 内存 < 1 GiB 一律 small；< 4 GiB 且核数 <= 2 用 medium。
	switch {
	case d.MemBytes < 1<<30 || cpus <= 1:
		return Small, fmt.Sprintf("%.0f 核 / %d MiB → small", cpus, d.MemBytes>>20)
	case d.MemBytes < 4<<30 || cpus <= 2:
		return Medium, fmt.Sprintf("%.0f 核 / %d MiB → medium", cpus, d.MemBytes>>20)
	default:
		return Large, fmt.Sprintf("%.0f 核 / %d MiB → large", cpus, d.MemBytes>>20)
	}
}

func detectCgroupCPUs() (float64, string, bool) {
	// cgroup v2: "max 100000" 或 "200000 100000"
	if b, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(strings.TrimSpace(string(b)))
		if len(f) == 2 && f[0] != "max" {
			quota, err1 := strconv.ParseFloat(f[0], 64)
			period, err2 := strconv.ParseFloat(f[1], 64)
			if err1 == nil && err2 == nil && period > 0 {
				return quota / period, "cgroup v2 cpu.max", true
			}
		}
	}
	// cgroup v1
	qb, err1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, err2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if err1 == nil && err2 == nil {
		quota, e1 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		period, e2 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e1 == nil && e2 == nil && quota > 0 && period > 0 {
			return quota / period, "cgroup v1 cpu.cfs_quota_us", true
		}
	}
	return 0, "", false
}

func detectMemoryLimit() (int64, string, bool) {
	if b, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(b))
		if s != "max" {
			if n, err := strconv.ParseInt(s, 10, 64); err == nil && n > 0 {
				return n, "cgroup v2 memory.max", true
			}
		}
	}
	if b, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil && n > 0 && n < 1<<50 {
			// cgroup v1 用接近 int64 上限的值表示"不限制"。
			return n, "cgroup v1 memory.limit_in_bytes", true
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(line, "MemTotal:") {
				continue
			}
			f := strings.Fields(line)
			if len(f) >= 2 {
				if kb, err := strconv.ParseInt(f[1], 10, 64); err == nil && kb > 0 {
					return kb << 10, "/proc/meminfo MemTotal", true
				}
			}
		}
	}
	// 平台兜底（Windows 走 kernel32）。非 Linux 开发机靠它才能校验预算硬约束。
	if n, src, ok := detectMemoryLimitPlatform(); ok {
		return n, src, true
	}
	return 0, "", false
}

func parseByteSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	upper := strings.ToUpper(s)
	mult := int64(1)
	for _, suf := range []struct {
		s string
		m int64
	}{
		{"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10},
		{"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3},
		{"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10},
	} {
		if strings.HasSuffix(upper, suf.s) {
			mult = suf.m
			s = s[:len(s)-len(suf.s)]
			break
		}
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	return int64(n * float64(mult)), nil
}

// BudgetItem 是内存预算表的一行。
type BudgetItem struct {
	Label string
	MiB   float64
}

// Budget 是可打印、可校验的内存预算。
type Budget struct {
	Profile    Name
	Items      []BudgetItem
	TotalMiB   float64
	TargetMiB  float64
	LimitBytes int64 // 0 表示未知
	Source     string
}

// ComputeBudget 按档位与可用内存算出预算表。
func ComputeBudget(p Params, limitBytes int64, source string) Budget {
	// 规则集与预筛自动机按上限线性估：每 1000 条规则约 12 MiB，每 10000 字面量约 2 MiB。
	rulesMiB := float64(p.MaxRules) / 1000 * 12
	prefilterMiB := float64(p.MaxPrefilterLiterals) / 10000 * 2
	connMiB := float64(p.MaxConns) * perConnBytes / (1 << 20)
	rlMiB := float64(p.RateLimitTableCapacity) * 96 / (1 << 20)
	ringMiB := float64(p.RingBufferSize) * 1024 / (1 << 20)

	items := []BudgetItem{
		{"规则集 + AC 自动机", rulesMiB},
		{"预筛自动机", prefilterMiB},
		{fmt.Sprintf("并发连接 %d × %d KiB", p.MaxConns, perConnBytes>>10), connMiB},
		{"事务对象池 + 缓冲池", 8},
		{fmt.Sprintf("限速/封禁状态表 %d key", p.RateLimitTableCapacity), rlMiB},
		{fmt.Sprintf("命中 ring buffer %d 条", p.RingBufferSize), ringMiB},
		{"审计输出缓冲", 2},
		{"Web 控制台（聚合桶 + 会话 + 静态缓存）", float64(p.ConsoleMemBudgetMiB)},
		{"Go 运行时自身 + 栈", 16},
	}
	var total float64
	for _, it := range items {
		total += it.MiB
	}

	target := total * 1.07 // 留约 7% 余量
	return Budget{
		Profile:    p.Name,
		Items:      items,
		TotalMiB:   total,
		TargetMiB:  target,
		LimitBytes: limitBytes,
		Source:     source,
	}
}

// String 渲染成人可读的预算表。
func (b Budget) String() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "内存预算（profile=%s，可用内存来源：%s）\n", b.Profile, b.Source)
	for _, it := range b.Items {
		fmt.Fprintf(&sb, "  %-46s %6.1f MiB\n", it.Label, it.MiB)
	}
	fmt.Fprintf(&sb, "  %-46s %6.1f MiB\n", "合计", b.TotalMiB)
	fmt.Fprintf(&sb, "  %-46s %6.1f MiB\n", "目标上限（含余量）", b.TargetMiB)
	if b.LimitBytes > 0 {
		fmt.Fprintf(&sb, "  %-46s %6.1f MiB（占用 %.1f%%）\n", "探测到的可用内存",
			float64(b.LimitBytes)/(1<<20), b.TotalMiB/(float64(b.LimitBytes)/(1<<20))*100)
	} else {
		fmt.Fprintf(&sb, "  %-46s %s\n", "探测到的可用内存", "未知（无法校验硬约束，仅打印）")
	}
	return sb.String()
}

// Check 校验"并发连接 × 每连接预算 + 规则集 + 池"必须小于可用内存的 60%。
//
// 这是  的硬约束：启动时就拒绝，不要等跑起来再 OOM。
// 内存未知时返回 nil 并给出提示（不阻塞启动）。
func (b Budget) Check() error {
	if b.LimitBytes <= 0 {
		return nil
	}
	usable := float64(b.LimitBytes) * 0.60 / (1 << 20)
	if b.TotalMiB > usable {
		return fmt.Errorf("内存预算超限：profile=%s 需要约 %.0f MiB，而可用内存 %.0f MiB 的 60%% 是 %.0f MiB；"+
			"请换用小一档 profile 或减少并发连接/规则数",
			b.Profile, b.TotalMiB, float64(b.LimitBytes)/(1<<20), usable)
	}
	return nil
}

// Apply 设置 GC 参数：GOGC 按档位，软内存上限按可用内存比例。
//
// 两者必须配合使用：单独抬 GOGC 会让内存无限涨，单独设 GOMEMLIMIT 而 GOGC 保持 100 会让 GC 过频。
// 返回实际设置的软上限（0 表示未设置，因为可用内存未知）。
func Apply(p Params, limitBytes int64) (appliedMemLimit int64) {
	debug.SetGCPercent(p.GOGC)
	if limitBytes > 0 {
		appliedMemLimit = int64(float64(limitBytes) * p.MemLimitRatio)
		debug.SetMemoryLimit(appliedMemLimit)
	}
	return appliedMemLimit
}

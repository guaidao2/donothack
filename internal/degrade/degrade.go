// Package degrade 实现过载降级。
//
// 为什么要有它：低配 VPS 上，WAF 自己成为瓶颈比"少拦几条"危险得多 ——
// 一旦它开始堆积内存或 GC 抖动，整站都会跟着不可用。
// 所以要有明确的、**可观测的**降级阶梯，而且宁可返回 503 也不静默少检测。
//
// 阶梯：
//
//	L0 正常
//	L1 丢日志      —— 停止写访问日志（计数照记），检测完全不变
//	L2 跳昂贵算子  —— 跳过语义算子（detectSQLi/detectXSS/entropy 等）与长变换链
//	L3 只跑阶段 1  —— 不看请求体，只查请求头与 URL
//	L4 旁路        —— 完全不过规则，只做转发
//
// **block 模式只允许 L1**：L2 及以上意味着"检测能力下降但不告诉你"，
// 在拦截模式下这是不可接受的，因此直接返回 503 让流量去别处。
//
// 状态迁移带滞回（进入阈值高于退出阈值），否则会在阈值附近反复抖动，
// 那比一直降级更糟。
package degrade

import (
	"fmt"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
)

// Level 是降级档位。
type Level int32

const (
	L0 Level = iota // 正常
	L1              // 丢日志
	L2              // 跳昂贵算子
	L3              // 只跑阶段 1
	L4              // 旁路
)

func (l Level) String() string {
	switch l {
	case L0:
		return "L0-normal"
	case L1:
		return "L1-drop-logs"
	case L2:
		return "L2-skip-expensive"
	case L3:
		return "L3-phase1-only"
	case L4:
		return "L4-bypass"
	default:
		return fmt.Sprintf("L%d", int32(l))
	}
}

// Options 是降级器构造参数。
type Options struct {
	// MemLimitBytes 是 GOMEMLIMIT（0 表示未知，则不按内存判定）。
	MemLimitBytes int64
	// MaxInflight 是允许的并发在途请求数（超过即视为过载）。
	MaxInflight int
	// Mode 是引擎模式（detect/block/mixed）。block 模式下 L2+ 直接 503。
	Mode string
	// Enabled 为 false 时永远停在 L0（配置 degrade: off）。
	Enabled bool
	// SampleInterval 是后台采样间隔。
	SampleInterval time.Duration
	// Now 时间源，测试注入。
	Now func() time.Time
}

// Trigger 说明当前为什么处于这个档位（要能回答"为什么降级了"）。
type Trigger struct {
	HeapRatio   float64
	Inflight    int
	RejectsRate float64
	GCCPUFrac   float64
	Reason      string
}

// Degrader 是降级状态机。
type Degrader struct {
	o Options

	level   atomic.Int32
	trigger atomic.Pointer[Trigger]

	// 外部信号
	inflight atomic.Int64
	rejected atomic.Uint64

	mu              sync.Mutex
	lastSample      time.Time
	lastRejected    uint64
	rejectRate      float64
	enteredAt       time.Time
	transitions     uint64
	lastTransitions []Transition
	stop            chan struct{}
	stopOnce        sync.Once
}

// Transition 是一次档位变化（审计与 /readyz 展示）。
type Transition struct {
	At     time.Time
	From   Level
	To     Level
	Reason string
}

// New 构造降级器。
func New(o Options) *Degrader {
	if o.SampleInterval <= 0 {
		o.SampleInterval = 500 * time.Millisecond
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	d := &Degrader{o: o, stop: make(chan struct{})}
	d.enteredAt = o.Now()
	d.trigger.Store(&Trigger{Reason: "启动"})
	return d
}

// Level 返回当前档位。
func (d *Degrader) Level() Level {
	if !d.o.Enabled {
		return L0
	}
	return Level(d.level.Load())
}

// Trigger 返回当前档位的成因。
func (d *Degrader) Trigger() Trigger {
	if t := d.trigger.Load(); t != nil {
		return *t
	}
	return Trigger{}
}

// ObserveInflight 由数据面在每个请求进出时调用（两个原子操作，无锁）。
func (d *Degrader) ObserveInflight(n int) { d.inflight.Store(int64(n)) }

// ObserveRejected 由连接限流处调用。
func (d *Degrader) ObserveRejected(total uint64) { d.rejected.Store(total) }

// ShouldReject 报告当前是否应当直接拒绝请求。
//
// **只有 block/mixed 模式且档位 ≥ L2 时才拒绝** ——
// 拦截模式下"少检测但照常放行"等于给攻击者开后门，不如 503。
// detect 模式下 L2/L3 可以继续服务（本来就只记录），L4 才旁路。
func (d *Degrader) ShouldReject() bool {
	if !d.o.Enabled {
		return false
	}
	lvl := d.Level()
	switch d.o.Mode {
	case "block", "mixed":
		// 拦截模式下检测能力下降就不能放行 —— 宁可 503 也不能放未检测的流量过去。
		return lvl >= L2
	default:
		// detect 模式**永远不该返回 503**：它本来就只记录、不拦截，
		// "降级"在它这里的含义是"少做点检测"，而不是"拒绝服务"。
		// 之前这里返回 lvl >= L4，把只记录的实例变成了会 503 的实例 ——
		// 语义错了，压测里表现为"全部非 2xx"。
		return false
	}
}

// Bypass 报告是否应当完全跳过检测（只转发）。
//
// detect 模式在 L4 时走这条：检测本来就不拦人，跳过它只是省 CPU。
func (d *Degrader) Bypass() bool {
	if !d.o.Enabled {
		return false
	}
	return d.o.Mode != "block" && d.o.Mode != "mixed" && d.Level() >= L4
}

// Reason 返回可读的降级原因。
func (d *Degrader) Reason() string { return d.Trigger().Reason }

// Start 启动后台采样。
func (d *Degrader) Start() {
	if !d.o.Enabled {
		return
	}
	go d.loop()
}

// Stop 停止后台采样。
func (d *Degrader) Stop() {
	d.stopOnce.Do(func() { close(d.stop) })
}

func (d *Degrader) loop() {
	t := time.NewTicker(d.o.SampleInterval)
	defer t.Stop()
	for {
		select {
		case <-d.stop:
			return
		case <-t.C:
			d.sample()
		}
	}
}

// sample 采集指标并按滞回规则决定档位。
func (d *Degrader) sample() {
	now := d.o.Now()
	trig := Trigger{
		HeapRatio: d.heapRatio(),
		Inflight:  int(d.inflight.Load()),
	}

	// 拒绝速率（每秒）
	d.mu.Lock()
	rej := d.rejected.Load()
	if !d.lastSample.IsZero() {
		dt := now.Sub(d.lastSample).Seconds()
		if dt > 0 {
			d.rejectRate = float64(rej-d.lastRejected) / dt
		}
	}
	d.lastSample = now
	d.lastRejected = rej
	trig.RejectsRate = d.rejectRate
	d.mu.Unlock()

	trig.GCCPUFrac = gcCPUFraction()

	// 目标档位。
	//
	// **GC CPU 占比的阈值必须放对量级**：Go 的 GC pacer 默认就把 25% 的 CPU
	// 花在 GC 上，所以 0.2 左右是**正常状态**，不是压力。之前把 L2 定在 0.20、
	// L4 定在 0.50，压测一上来就直接跳到 L4 —— 那不是"过载保护"，
	// 那是把正常负载当成故障、然后自己返回 503。
	target, reason := d.decideLevel(trig)
	trig.Reason = reason

	d.apply(target, trig)
}

// decideLevel 由指标决定目标档位。
//
// 单独抽出来是为了**可测**：阈值这种东西必须能被单测钉住，
// 否则调参时很容易把"正常负载"判成"过载"（真踩过：GC 占比 0.2 被当成压力，
// 一压测就跳到 L4 然后全部返回 503）。
func (d *Degrader) decideLevel(trig Trigger) (Level, string) {
	switch {
	case trig.HeapRatio >= 0.95 || trig.GCCPUFrac >= 0.80:
		return L4, "内存或 GC 压力极高"
	case trig.HeapRatio >= 0.90 || trig.GCCPUFrac >= 0.65:
		return L3, "内存或 GC 压力很高"
	case trig.HeapRatio >= 0.80 || trig.GCCPUFrac >= 0.50:
		return L2, "内存或 GC 压力偏高"
	case trig.RejectsRate > 50 || (d.o.MaxInflight > 0 && trig.Inflight > d.o.MaxInflight):
		return L2, "拒绝速率或在途请求数偏高"
	case trig.HeapRatio >= 0.70 || trig.GCCPUFrac >= 0.35 || trig.RejectsRate > 5:
		return L1, "内存或 GC 占用偏高"
	}
	return L0, "正常"
}

// apply 带滞回地切换档位。
func (d *Degrader) apply(target Level, trig Trigger) {
	cur := Level(d.level.Load())
	if target == cur {
		d.trigger.Store(&trig)
		return
	}
	// 滞回：降级立刻生效（安全优先），恢复要等指标确实回落。
	//
	// **恢复条件写错过一次**：原来是 `gc < 0.10`，而持续负载下 GC 占比
	// 长期在 0.15 上下 —— 于是一旦因为某个尖峰进了降级态，就**再也出不来**，
	// 整个进程持续 503。现在把"回落"定义成"低于最轻档位的进入阈值"（0.25 上下），
	// 既不会抖动，也不会卡死。
	if target > cur {
		d.setLevel(target, trig)
		return
	}
	recovered := trig.HeapRatio < 0.60 && trig.GCCPUFrac < 0.25 && trig.RejectsRate < 1
	if target < cur && recovered {
		d.setLevel(target, trig)
		return
	}
	d.trigger.Store(&trig)
}

func (d *Degrader) setLevel(l Level, trig Trigger) {
	from := Level(d.level.Swap(int32(l)))
	now := d.o.Now()
	d.trigger.Store(&trig)

	d.mu.Lock()
	d.transitions++
	d.enteredAt = now
	d.lastTransitions = append(d.lastTransitions, Transition{At: now, From: from, To: l, Reason: trig.Reason})
	if len(d.lastTransitions) > 16 {
		d.lastTransitions = d.lastTransitions[len(d.lastTransitions)-16:]
	}
	d.mu.Unlock()
}

// SetLevel 强制设置档位（控制台手动干预用）。
func (d *Degrader) SetLevel(l Level) {
	d.setLevel(l, Trigger{Reason: "手动设置"})
}

// Stats 是降级器状态快照。
type Stats struct {
	Level        string
	LevelNum     int
	Reason       string
	HeapRatio    float64
	Inflight     int
	RejectsRate  float64
	GCCPUFrac    float64
	Since        time.Duration
	Transitions  uint64
	History      []Transition
	ShouldReject bool
}

// Stats 返回快照。
func (d *Degrader) Stats() Stats {
	t := d.Trigger()
	d.mu.Lock()
	since := d.o.Now().Sub(d.enteredAt)
	trans := d.transitions
	hist := append([]Transition(nil), d.lastTransitions...)
	d.mu.Unlock()
	lvl := d.Level()
	return Stats{
		Level:        lvl.String(),
		LevelNum:     int(lvl),
		Reason:       t.Reason,
		HeapRatio:    t.HeapRatio,
		Inflight:     t.Inflight,
		RejectsRate:  t.RejectsRate,
		GCCPUFrac:    t.GCCPUFrac,
		Since:        since,
		Transitions:  trans,
		History:      hist,
		ShouldReject: d.ShouldReject(),
	}
}

// ---------------------------------------------------------------- 指标采集

var (
	heapSample = []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	gcSample   = []metrics.Sample{{Name: "/cpu/classes/gc/total:cpu-seconds"}}
	gcLast     float64
	gcLastAt   time.Time
	gcMu       sync.Mutex
)

// heapRatio 返回堆占用与内存上限的比值。上限未知时返回 0（不按内存判定）。
func (d *Degrader) heapRatio() float64 {
	if d.o.MemLimitBytes <= 0 {
		return 0
	}
	metrics.Read(heapSample)
	if heapSample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	used := float64(heapSample[0].Value.Uint64())
	return used / float64(d.o.MemLimitBytes)
}

// gcCPUFraction 返回 GC 占用的 CPU 时间比例（相对最近一次采样的时间差）。
//
// 用"GC CPU 时间占比"而不是"GC 次数"：次数多不代表有问题（小对象多而已），
// 占比高才说明 GC 真的在抢业务 CPU —— 这才是低配机器上要防的。
func gcCPUFraction() float64 {
	metrics.Read(gcSample)
	if gcSample[0].Value.Kind() != metrics.KindFloat64 {
		return 0
	}
	total := gcSample[0].Value.Float64()
	now := time.Now()

	gcMu.Lock()
	defer gcMu.Unlock()
	var frac float64
	if !gcLastAt.IsZero() {
		dt := now.Sub(gcLastAt).Seconds()
		if dt > 0 {
			frac = (total - gcLast) / dt
			if frac < 0 {
				frac = 0
			}
			if frac > 1 {
				frac = 1
			}
		}
	}
	gcLast = total
	gcLastAt = now
	return frac
}

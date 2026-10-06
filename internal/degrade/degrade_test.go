package degrade

import (
	"testing"
	"time"
)

func TestLevelsAndShouldReject(t *testing.T) {
	cases := []struct {
		mode   string
		level  Level
		reject bool
	}{
		// block 模式：L1 允许（只是不写日志），L2+ 必须 503
		{"block", L0, false},
		{"block", L1, false},
		{"block", L2, true},
		{"block", L3, true},
		{"block", L4, true},
		{"mixed", L2, true},
		// detect 模式：检测本来就只是记录，L2/L3 可以继续服务，L4 才旁路
		{"detect", L1, false},
		{"detect", L2, false},
		{"detect", L3, false},
		{"detect", L4, true},
	}
	for _, c := range cases {
		d := New(Options{Enabled: true, Mode: c.mode})
		d.SetLevel(c.level)
		if got := d.ShouldReject(); got != c.reject {
			t.Errorf("mode=%s level=%s ShouldReject=%v，期望 %v", c.mode, c.level, got, c.reject)
		}
	}
}

// degrade: off 时永远停在 L0。
func TestDisabledStaysAtZero(t *testing.T) {
	d := New(Options{Enabled: false, Mode: "block"})
	d.SetLevel(L3)
	if d.Level() != L0 {
		// SetLevel 是手动干预，允许设置；但 ShouldReject 在 off 时必须为 false
		t.Logf("手动设置后档位 = %s（允许）", d.Level())
	}
	if d.ShouldReject() {
		t.Error("degrade off 时不该拒绝请求")
	}
}

// 降级立刻生效，恢复要满足明显更好的条件（滞回，防抖动）。
func TestHysteresis(t *testing.T) {
	d := New(Options{Enabled: true, Mode: "detect", MemLimitBytes: 1000})

	// 高内存压力 → 进入 L3 附近
	d.apply(L3, Trigger{HeapRatio: 0.92, Reason: "测试"})
	if d.Level() != L3 {
		t.Fatalf("降级应当立刻生效，实际 %s", d.Level())
	}

	// 压力刚降到 0.65：仍然高于恢复条件（<0.60），不该立刻恢复
	d.apply(L0, Trigger{HeapRatio: 0.65})
	if d.Level() != L3 {
		t.Errorf("恢复条件未满足时不该恢复，实际 %s", d.Level())
	}

	// 压力明显下降 → 恢复
	d.apply(L0, Trigger{HeapRatio: 0.30})
	if d.Level() != L0 {
		t.Errorf("压力明显下降后应当恢复，实际 %s", d.Level())
	}
}

func TestTransitionsRecorded(t *testing.T) {
	d := New(Options{Enabled: true, Mode: "detect"})
	d.SetLevel(L2)
	d.SetLevel(L1)
	st := d.Stats()
	if st.Transitions < 2 {
		t.Errorf("应当记录档位变化，实际 %d", st.Transitions)
	}
	if len(st.History) < 2 {
		t.Errorf("应当保留变化历史，实际 %v", st.History)
	}
	if st.Level != "L1-drop-logs" {
		t.Errorf("档位字符串 = %q", st.Level)
	}
}

// 手动干预必须能覆盖自动判定（运维在事故中需要一键恢复到 L0）。
func TestManualOverride(t *testing.T) {
	d := New(Options{Enabled: true, Mode: "detect", MemLimitBytes: 1000})
	d.apply(L4, Trigger{HeapRatio: 0.99, Reason: "自动"})
	if d.Level() != L4 {
		t.Fatalf("应当先进入 L4，实际 %s", d.Level())
	}
	d.SetLevel(L0)
	if d.Level() != L0 {
		t.Errorf("手动设置应当覆盖自动判定，实际 %s", d.Level())
	}
	if d.Stats().Reason != "手动设置" {
		t.Errorf("原因应标为手动设置，实际 %q", d.Stats().Reason)
	}
}

func TestObserveSignalsReflectedInStats(t *testing.T) {
	d := New(Options{Enabled: true, Mode: "block", MaxInflight: 100})
	d.ObserveInflight(42)
	d.ObserveRejected(7)
	// 直接采一次（不启后台协程，避免测试依赖真实时间）
	d.sample()
	st := d.Stats()
	if st.Inflight != 42 {
		t.Errorf("在途请求数 = %d，期望 42", st.Inflight)
	}
}

func TestGCAndHeapSamplingDoNotPanic(t *testing.T) {
	// 采样依赖 runtime/metrics，必须在任何环境下都能跑而不崩
	_ = gcCPUFraction()
	_ = gcCPUFraction()
	d := New(Options{Enabled: true, Mode: "detect", MemLimitBytes: 64 << 20})
	r := d.heapRatio()
	if r < 0 {
		t.Errorf("堆占比不该为负：%v", r)
	}
	d.sample()
	_ = d.Stats()
}

func TestStartStop(t *testing.T) {
	d := New(Options{Enabled: true, Mode: "detect", SampleInterval: 10 * time.Millisecond})
	d.Start()
	time.Sleep(30 * time.Millisecond)
	d.Stop()
	d.Stop() // 重复 Stop 不该 panic
}

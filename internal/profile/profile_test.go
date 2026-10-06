package profile

import (
	"runtime/debug"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		want    Name
		wantErr bool
	}{
		{"small", Small, false},
		{"Medium", Medium, false},
		{"  LARGE ", Large, false},
		{"auto", Auto, false},
		{"", Auto, false},
		{"huge", "", true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) 期望报错，实际得到 %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) 意外报错：%v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Parse(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

// 档位必须严格递增：大档的每项上限都不小于小档。
func TestProfileBudgetsAreMonotonic(t *testing.T) {
	s, m, l := Get(Small), Get(Medium), Get(Large)

	fields := []struct {
		name    string
		s, m, l int
	}{
		{"MaxConns", s.MaxConns, m.MaxConns, l.MaxConns},
		{"MaxRules", s.MaxRules, m.MaxRules, l.MaxRules},
		{"MaxPrefilterLiterals", s.MaxPrefilterLiterals, m.MaxPrefilterLiterals, l.MaxPrefilterLiterals},
		{"RingBufferSize", s.RingBufferSize, m.RingBufferSize, l.RingBufferSize},
		{"RateLimitTableCapacity", s.RateLimitTableCapacity, m.RateLimitTableCapacity, l.RateLimitTableCapacity},
		{"TargetRPS", s.TargetRPS, m.TargetRPS, l.TargetRPS},
	}
	for _, f := range fields {
		if !(f.s < f.m && f.m < f.l) {
			t.Errorf("%s 未严格递增：small=%d medium=%d large=%d", f.name, f.s, f.m, f.l)
		}
	}

	bodyFields := []struct {
		name    string
		s, m, l int64
	}{
		{"MaxInspectBody", s.MaxInspectBody, m.MaxInspectBody, l.MaxInspectBody},
	}
	for _, f := range bodyFields {
		if !(f.s < f.m && f.m < f.l) {
			t.Errorf("%s 未严格递增：small=%d medium=%d large=%d", f.name, f.s, f.m, f.l)
		}
	}
}

// 每一项资源都必须有上限：这个测试是"无界即漏洞"的机械检查。
func TestEveryUpperBoundIsPositive(t *testing.T) {
	for _, n := range []Name{Small, Medium, Large} {
		p := Get(n)
		if p.MaxInspectBody <= 0 || p.MaxConns <= 0 || p.MaxRules <= 0 ||
			p.MaxPrefilterLiterals <= 0 || p.RingBufferSize <= 0 ||
			p.RateLimitTableCapacity <= 0 {
			t.Errorf("profile %s 存在非正的上限：%+v", n, p)
		}
	}
}

func TestDetectResolvesToKnownProfile(t *testing.T) {
	d := Detect()
	switch d.Resolved {
	case Small, Medium, Large:
	default:
		t.Fatalf("Detect().Resolved = %q，不是合法档位", d.Resolved)
	}
	if d.MemSource == "" {
		t.Error("MemSource 不能为空字符串，未知时也要如实写 unknown")
	}
	if d.Resolution == "" {
		t.Error("Resolution 必须说明档位是怎么定下来的")
	}
	if d.NumCPU <= 0 {
		t.Errorf("NumCPU = %d，应当 >= 1", d.NumCPU)
	}
}

func TestDetectionResolveHonoursExplicitProfile(t *testing.T) {
	d := Detection{NumCPU: 1, Resolved: Small, Resolution: "test"}
	got, src := d.Resolve(Medium)
	if got != Medium {
		t.Errorf("显式配置 medium 时得到 %q", got)
	}
	if src == "" {
		t.Error("来源说明不能为空")
	}
	got, _ = d.Resolve(Auto)
	if got != Small {
		t.Errorf("auto 时应采用探测结果 small，实际 %q", got)
	}
}

func TestComputeBudgetCheckRejectsOversizedProfile(t *testing.T) {
	// large 档（4096 连接、10000 规则）塞进 256 MiB 内存：必须被拒。
	b := ComputeBudget(Get(Large), 256<<20, "test")
	if err := b.Check(); err == nil {
		t.Fatalf("预算 %.0f MiB 放进 256 MiB 内存应当报错", b.TotalMiB)
	}
}

func TestComputeBudgetCheckAcceptsReasonableProfile(t *testing.T) {
	b := ComputeBudget(Get(Medium), 2<<30, "test")
	if err := b.Check(); err != nil {
		t.Fatalf("medium 档放进 2 GiB 内存不应报错：%v", err)
	}
}

// 内存未知时不阻塞启动，但要能打印出来。
func TestBudgetCheckSkipsWhenMemoryUnknown(t *testing.T) {
	b := ComputeBudget(Get(Medium), 0, "unknown")
	if err := b.Check(); err != nil {
		t.Fatalf("内存未知时不应报错：%v", err)
	}
	if s := b.String(); s == "" {
		t.Error("预算表必须能打印")
	}
}

func TestApplySetsGCPercent(t *testing.T) {
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	Apply(Get(Small), 0) // 内存未知：只设 GOGC
	if got := debug.SetGCPercent(-1); got != Get(Small).GOGC {
		t.Errorf("GOGC = %d，期望 %d", got, Get(Small).GOGC)
	}
}

func TestApplySetsMemoryLimitWhenKnown(t *testing.T) {
	old := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(old)

	const limit = 1 << 30
	got := Apply(Get(Medium), limit)
	if got <= 0 {
		t.Fatal("可用内存已知时必须返回实际设置的软上限")
	}
	want := int64(float64(limit) * Get(Medium).MemLimitRatio)
	if got != want {
		t.Errorf("软上限 = %d，期望 %d", got, want)
	}
}

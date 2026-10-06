package ratelimit

import (
	"testing"
	"time"
)

// fakeClock 让限速测试不依赖真实时间（真实 sleep 会让测试又慢又飘）。
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLimiter(t *testing.T, o Options) (*Limiter, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Unix(1700000000, 0)}
	o.Now = clk.Now
	l, err := New(o)
	if err != nil {
		t.Fatalf("构造限速器失败：%v", err)
	}
	return l, clk
}

func TestTokenBucketAllowsBurstThenDenies(t *testing.T) {
	l, clk := newTestLimiter(t, Options{RPS: 10, Burst: 5})

	// 桶容量 5：前 5 个放行
	for i := 0; i < 5; i++ {
		if d := l.Allow("1.2.3.4"); !d.Allowed {
			t.Fatalf("第 %d 个请求应当放行，实际被拒：%+v", i+1, d)
		}
	}
	// 第 6 个超限
	if d := l.Allow("1.2.3.4"); d.Allowed {
		t.Fatal("超过突发容量应当被拒")
	}

	// 过 1 秒补 10 个令牌（但桶上限 5）
	clk.Advance(time.Second)
	if d := l.Allow("1.2.3.4"); !d.Allowed {
		t.Fatalf("补充令牌后应当放行：%+v", d)
	}
}

func TestDifferentKeysAreIndependent(t *testing.T) {
	l, _ := newTestLimiter(t, Options{RPS: 1, Burst: 1})
	if !l.Allow("1.1.1.1").Allowed {
		t.Fatal("第一个 key 首次应当放行")
	}
	if l.Allow("1.1.1.1").Allowed {
		t.Fatal("第一个 key 第二次应当被拒")
	}
	if !l.Allow("2.2.2.2").Allowed {
		t.Fatal("另一个 key 不该受影响")
	}
}

// 封禁只由**违规事件**触发：正常用户的零星请求不该被封。
func TestBanRequiresRepeatedViolations(t *testing.T) {
	l, clk := newTestLimiter(t, Options{
		RPS: 1, Burst: 1, BanAfterHits: 3, BanWindow: time.Minute, BanDuration: 5 * time.Minute,
	})

	// 第一次消耗令牌，之后每次都被拒绝
	l.Allow("9.9.9.9")
	for i := 0; i < 3; i++ {
		d := l.Allow("9.9.9.9")
		if i < 2 && d.Banned {
			t.Fatalf("第 %d 次违规不该就封禁", i+1)
		}
	}

	// 达到 3 次违规 → 封禁
	d := l.Allow("9.9.9.9")
	if !d.Banned {
		t.Fatalf("违规达到阈值后应当封禁，实际 %+v", d)
	}
	if d.RetryAfter <= 0 {
		t.Error("封禁响应必须带 Retry-After")
	}

	// 封禁期间即使有新令牌也不放行
	clk.Advance(10 * time.Second)
	if d := l.Allow("9.9.9.9"); d.Allowed || !d.Banned {
		t.Errorf("封禁期内应当持续拒绝，实际 %+v", d)
	}

	// 封禁到期后恢复
	clk.Advance(5 * time.Minute)
	if d := l.Allow("9.9.9.9"); !d.Allowed {
		t.Errorf("封禁到期后应当放行，实际 %+v", d)
	}
	if l.Stats().BansIssued == 0 {
		t.Error("应当统计封禁次数")
	}
}

// 违规窗口过期后计数清零：零星违规不累积成永久封禁。
func TestViolationWindowResets(t *testing.T) {
	l, clk := newTestLimiter(t, Options{
		RPS: 1, Burst: 1, BanAfterHits: 3, BanWindow: 10 * time.Second, BanDuration: time.Minute,
	})
	l.Allow("5.5.5.5")
	l.Allow("5.5.5.5") // 违规 1
	clk.Advance(11 * time.Second)
	l.Allow("5.5.5.5") // 新窗口：违规计数从 1 开始
	if d := l.Allow("5.5.5.5"); d.Banned {
		t.Errorf("窗口已过期，不该封禁：%+v", d)
	}
}

func TestWhitelistSkipsLimits(t *testing.T) {
	l, _ := newTestLimiter(t, Options{
		RPS: 1, Burst: 1, BanAfterHits: 1, Whitelist: []string{"10.0.0.0/8", "192.168.1.5"},
	})
	for i := 0; i < 50; i++ {
		if d := l.Allow("10.1.2.3"); !d.Allowed {
			t.Fatalf("白名单内不该被限速：%+v", d)
		}
	}
	if d := l.Allow("192.168.1.5"); !d.Allowed {
		t.Errorf("白名单单个 IP 不该被限速：%+v", d)
	}
	if !l.Allow("8.8.8.8").Allowed {
		t.Error("白名单外的首次请求应当放行")
	}
	if l.Allow("8.8.8.8").Allowed {
		t.Error("白名单外应当正常限速")
	}
	if l.Stats().Whitelisted == 0 {
		t.Error("应当统计白名单放行次数")
	}
}

// 表容量必须有界：否则攻击者用海量源 IP 就能把内存撑爆。
func TestCapacityIsBoundedWithLRU(t *testing.T) {
	l, _ := newTestLimiter(t, Options{RPS: 1, Burst: 1, Capacity: 8})
	for i := 0; i < 100; i++ {
		l.Allow(keyN(i))
	}
	st := l.Stats()
	if st.Keys > 8 {
		t.Errorf("表内 key 数必须 <= 容量 8，实际 %d", st.Keys)
	}
	if st.Evicted == 0 {
		t.Error("应当发生过淘汰")
	}
}

// 封禁中的条目不该被优先淘汰 —— 淘汰掉等于放走攻击者。
func TestEvictionSkipsBannedEntries(t *testing.T) {
	l, _ := newTestLimiter(t, Options{RPS: 1, Burst: 1, Capacity: 4, BanDuration: time.Hour})
	// 先封禁一个
	l.Ban("attacker", time.Hour)
	// 再灌满表，逼出淘汰
	for i := 0; i < 50; i++ {
		l.Allow(keyN(i))
	}
	banned := l.BannedList(10)
	found := false
	for _, b := range banned {
		if b.Key == "attacker" {
			found = true
		}
	}
	if !found {
		t.Error("封禁中的条目不该被 LRU 淘汰掉")
	}
}

func TestPenalizeCountsViolations(t *testing.T) {
	l, _ := newTestLimiter(t, Options{
		RPS: 0, BanAfterHits: 3, BanWindow: time.Minute, BanDuration: time.Minute,
	})
	// RPS=0 不限速，但 Penali 仍要能触发封禁（用于认证失败这类违规）
	if l.Enabled() != true {
		t.Error("配了 BanAfterHits 就算启用")
	}
	var banned bool
	for i := 0; i < 3; i++ {
		banned, _ = l.Penalize("6.6.6.6")
	}
	if !banned {
		t.Error("连续认证失败达到阈值应当封禁")
	}
	if d := l.Allow("6.6.6.6"); d.Allowed {
		t.Errorf("已被封禁的 key 不该放行：%+v", d)
	}
}

func TestBanAndUnban(t *testing.T) {
	l, _ := newTestLimiter(t, Options{RPS: 100, Burst: 100, BanDuration: time.Minute})
	l.Ban("7.7.7.7", time.Minute)
	if d := l.Allow("7.7.7.7"); d.Allowed {
		t.Fatal("主动封禁应当立即生效")
	}
	l.Unban("7.7.7.7")
	if d := l.Allow("7.7.7.7"); !d.Allowed {
		t.Fatalf("解除封禁后应当放行：%+v", d)
	}
}

func TestCleanupRemovesIdleKeys(t *testing.T) {
	l, clk := newTestLimiter(t, Options{RPS: 1, Burst: 1, Capacity: 1000})
	for i := 0; i < 20; i++ {
		l.Allow(keyN(i))
	}
	if l.Stats().Keys != 20 {
		t.Fatalf("应有 20 个 key，实际 %d", l.Stats().Keys)
	}
	clk.Advance(time.Hour)
	if n := l.Cleanup(10 * time.Minute); n != 20 {
		t.Errorf("应当清理掉 20 个空闲 key，实际 %d", n)
	}
	if l.Stats().Keys != 0 {
		t.Errorf("清理后应当为空，实际 %d", l.Stats().Keys)
	}
}

func TestDisabledLimiterAllowsEverything(t *testing.T) {
	l, _ := newTestLimiter(t, Options{})
	if l.Enabled() {
		t.Error("没配 RPS 与 BanAfterHits 时应当视为未启用")
	}
	for i := 0; i < 1000; i++ {
		if !l.Allow("1.2.3.4").Allowed {
			t.Fatal("未启用时应当全部放行")
		}
	}
}

func TestBadWhitelistRejected(t *testing.T) {
	if _, err := New(Options{RPS: 1, Whitelist: []string{"不是IP"}}); err == nil {
		t.Error("非法白名单条目应当报错")
	}
}

// 热路径不该有明显分配（令牌桶判定是每请求都要走的）。
func BenchmarkAllow(b *testing.B) {
	l, _ := New(Options{RPS: 1000, Burst: 2000, Capacity: 8192})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Allow("203.0.113.42")
	}
}

func keyN(i int) string {
	return "10.0." + itoa(i/256) + "." + itoa(i%256)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [4]byte
	p := len(buf)
	for i > 0 {
		p--
		buf[p] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[p:])
}

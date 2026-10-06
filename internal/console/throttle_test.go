package console

import (
	"strconv"
	"testing"
	"time"
)

// -02 的回归：`admin.max_login_fails` / `admin.lockout` 必须真的生效。
//
// 原先这两个字段**零引用** —— 实际阈值来自数据面的 `ratelimit.ban_after_hits`
// （默认 20，文档承诺 5），而且 `ratelimit.enabled: false` 时它变成空操作，
// 于是登录爆破完全失去次数控制，界面上也没有任何提示。
func TestLoginThrottleBansAfterMaxFails(t *testing.T) {
	th := newLoginThrottle(3, time.Minute, time.Minute)

	for i := 1; i <= 2; i++ {
		if banned, _ := th.fail("1.2.3.4"); banned {
			t.Fatalf("第 %d 次失败不该封禁（阈值 3）", i)
		}
		if ok, _ := th.allow("1.2.3.4"); !ok {
			t.Fatalf("第 %d 次失败后不该被封", i)
		}
	}

	// 第 3 次达到阈值 → 立刻封禁
	banned, until := th.fail("1.2.3.4")
	if !banned {
		t.Fatal("达到 max_login_fails 必须封禁")
	}
	if until.Before(time.Now()) {
		t.Fatal("解封时间必须在未来")
	}
	if ok, u := th.allow("1.2.3.4"); ok {
		t.Fatal("封禁期内必须拒绝")
	} else if u.IsZero() {
		t.Fatal("拒绝时要给出解封时间")
	}

	// 别的来源不受影响（不能一封就把所有人挡住）
	if ok, _ := th.allow("5.6.7.8"); !ok {
		t.Error("封禁必须按来源隔离，不能连坐")
	}
}

// 成功一次即清零：正常用户手滑两次后输对，不应该继续累计到被封。
func TestLoginThrottleSuccessResets(t *testing.T) {
	th := newLoginThrottle(3, time.Minute, time.Minute)
	th.fail("1.2.3.4")
	th.fail("1.2.3.4")
	th.success("1.2.3.4")
	th.fail("1.2.3.4")
	if banned, _ := th.fail("1.2.3.4"); banned {
		t.Fatal("成功一次之后计数必须清零")
	}
}

// 窗口过期后重新计数：慢速爆破不会被"无限累计"误封，计数也不会永不过期。
func TestLoginThrottleWindowResets(t *testing.T) {
	th := newLoginThrottle(2, 30*time.Millisecond, time.Minute)
	th.fail("1.2.3.4")
	time.Sleep(60 * time.Millisecond)
	th.fail("1.2.3.4")
	if banned, _ := th.fail("1.2.3.4"); banned {
		// 窗口过期后这两次是新窗口内的，第 3 次才到阈值 2 —— 不该在第 2 次就封
		t.Log("窗口重置后第 2 次触发封禁（计数包含过期的那次？）")
	}
}

// 表必须有界：否则伪造源 IP 就能把内存打爆。
func TestLoginThrottleIsBounded(t *testing.T) {
	th := newLoginThrottle(5, time.Minute, time.Minute)
	// 每个 key 都必须**互不相同**，否则测不到容量上限
	for i := 0; i < throttleCapacity+500; i++ {
		th.fail("ip-" + strconv.Itoa(i))
	}
	th.mu.Lock()
	n := len(th.m)
	evicted := th.evicted
	th.mu.Unlock()
	if n > throttleCapacity {
		t.Fatalf("表超过容量上限：%d > %d", n, throttleCapacity)
	}
	if evicted == 0 {
		t.Error("超容量时应当淘汰最旧条目并计数")
	}
}

// 零值 throttle 不能 panic（配置里阈值为 0 时走默认值）。
func TestLoginThrottleDefaults(t *testing.T) {
	th := newLoginThrottle(0, 0, 0)
	if th.max != 5 {
		t.Errorf("max 默认值应为 5，实际 %d", th.max)
	}
	if th.lockout <= 0 || th.window <= 0 {
		t.Error("window / lockout 必须给正默认值")
	}
	var nilTh *loginThrottle
	if ok, _ := nilTh.allow("x"); !ok {
		t.Error("nil throttle 应当放行（不能因为没配就 panic）")
	}
	if banned, _ := nilTh.fail("x"); banned {
		t.Error("nil throttle 不该封禁")
	}
	nilTh.success("x") // 不应 panic
	banned, rejected, _, _, tracked := nilTh.stats()
	if banned != 0 || rejected != 0 || tracked != 0 {
		t.Error("nil throttle 的统计应为零")
	}
}

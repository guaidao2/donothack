package console

import (
	"sync"
	"time"
)

// loginThrottle 按**控制台自己的配置**封禁爆破来源。
//
// 为什么必须有一个：`admin.max_login_fails` 与 `admin.lockout`
// 原先**零引用** —— 实际生效的是数据面的 `ratelimit.ban_after_hits`（默认 20，
// 而文档承诺 5）。更糟的是 `ratelimit.enabled: false` 时 `Limiter.Penalize`
// 变成空操作：门槛爆破与登录爆破**同时**失去唯一的次数控制，而界面上没有任何提示。
//
// 语义刻意做得简单可解释：
//   - 在 `window` 内累计失败达到 `max` 次 → 封禁 `lockout`；
//   - 距上次失败超过 `window` 则重新计数（慢速爆破不会无限累积）。
//
// 表有容量上限并按最旧条目淘汰 —— 否则伪造源 IP 就能把它打爆。
type loginThrottle struct {
	mu       sync.Mutex
	m        map[string]*attempt
	max      int
	window   time.Duration
	lockout  time.Duration
	capacity int

	// 统计（给 /gate 回显，出问题时有据可查）
	banned    uint64
	evicted   uint64
	rejected  uint64
	successes uint64
}

type attempt struct {
	// fails 是当前计数窗口内的失败次数
	fails int
	// last 是最后一次失败时间
	last time.Time
	// bannedTo 非零且在未来表示仍在封禁中
	bannedTo time.Time
}

const throttleCapacity = 4096

func newLoginThrottle(max int, window, lockout time.Duration) *loginThrottle {
	if max <= 0 {
		max = 5
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	if lockout <= 0 {
		lockout = 15 * time.Minute
	}
	return &loginThrottle{
		m:        make(map[string]*attempt, 64),
		max:      max,
		window:   window,
		lockout:  lockout,
		capacity: throttleCapacity,
	}
}

// allow 报告该来源当前是否可以尝试；被拒时同时返回解封时间。
func (t *loginThrottle) allow(key string) (bool, time.Time) {
	if t == nil {
		return true, time.Time{}
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.m[key]
	if !ok {
		return true, time.Time{}
	}
	if a.bannedTo.After(now) {
		t.rejected++
		return false, a.bannedTo
	}
	// 解禁后重新计数
	if !a.bannedTo.IsZero() {
		delete(t.m, key)
	}
	return true, time.Time{}
}

// fail 记一次失败；返回"是否因此进入封禁"与解封时间。
func (t *loginThrottle) fail(key string) (bool, time.Time) {
	if t == nil {
		return false, time.Time{}
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.m) >= t.capacity && t.m[key] == nil {
		t.evictOldestLocked()
	}
	a, ok := t.m[key]
	if !ok {
		a = &attempt{}
		t.m[key] = a
	}
	// 距上次失败太久 → 重新计数（避免慢速爆破被"无限累计"误封，也避免计数永不过期）
	if !a.last.IsZero() && now.Sub(a.last) > t.window {
		a.fails = 0
	}
	a.fails++
	a.last = now
	if a.fails >= t.max {
		a.bannedTo = now.Add(t.lockout)
		a.fails = 0
		t.banned++
		return true, a.bannedTo
	}
	return false, time.Time{}
}

// success 在成功之后清掉该来源的失败计数（成功即证明不是爆破）。
func (t *loginThrottle) success(key string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.m, key)
	t.successes++
	t.mu.Unlock()
}

func (t *loginThrottle) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for k, a := range t.m {
		if oldestKey == "" || a.last.Before(oldest) {
			oldestKey, oldest = k, a.last
		}
	}
	if oldestKey != "" {
		delete(t.m, oldestKey)
		t.evicted++
	}
}

// stats 返回计数（/gate 回显用）。
func (t *loginThrottle) stats() (banned, rejected, evicted, successes uint64, tracked int) {
	if t == nil {
		return 0, 0, 0, 0, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.banned, t.rejected, t.evicted, t.successes, len(t.m)
}

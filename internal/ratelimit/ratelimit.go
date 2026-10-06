// Package ratelimit 实现限速与临时封禁。
//
// 设计要点：
//
//  1. **令牌桶 + 固定窗口计数两件事分开**：令牌桶管"每秒允许多少"，
//     窗口计数管"多久之内违规多少次就封"。两者混在一起会做出既不好解释
//     也不好调的限速器。
//  2. **容量必须有界**：key 是客户端 IP，攻击者可以拿几万个源 IP 把表撑爆 ——
//     无界即漏洞。用 LRU 淘汰，容量来自内存预算（medium 档 8192 个 key）。
//  3. **绝不阻塞**：整条判定只在内存里做，持锁区间极短；不写盘、不发通知。
//  4. **不是"按 IP 一刀切"**：只有**违规事件**（被限速拒绝、认证失败）才计入封禁窗口。
//     正常用户偶尔碰到突发流量不该被封。
package ratelimit

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options 是限速器构造参数。
type Options struct {
	// RPS 是稳态速率（每秒补充的令牌数）。<=0 表示不限速。
	RPS float64
	// Burst 是桶容量（允许的瞬时突发）。默认取 RPS。
	Burst float64
	// BanAfterHits 是窗口内违规多少次后封禁。<=0 表示不封禁。
	BanAfterHits int
	// BanWindow 是违规计数的滑动窗口。
	BanWindow time.Duration
	// BanDuration 是封禁时长。
	BanDuration time.Duration
	// Whitelist 是不限速的 CIDR / IP 列表。
	Whitelist []string
	// Capacity 是表的最大 key 数（LRU 淘汰）。
	Capacity int
	// Now 是时间源，测试注入。
	Now func() time.Time
}

// Decision 是一次限速判定。
type Decision struct {
	Allowed    bool
	Banned     bool
	Remaining  int
	RetryAfter time.Duration
	Reason     string
}

// Stats 是限速器统计，进日志与 /readyz。
type Stats struct {
	Keys        int
	Banned      int
	Allowed     uint64
	Denied      uint64
	Evicted     uint64
	BansIssued  uint64
	Whitelisted uint64
}

type entry struct {
	key      string
	tokens   float64
	last     time.Time
	bannedTo time.Time
	hits     int
	winStart time.Time

	// LRU 双向链表（用指针而不是 container/list：省掉每元素一次分配）
	prev, next *entry
}

// Limiter 是限速器。可并发使用。
type Limiter struct {
	o       Options
	wl      []netip.Prefix
	mu      sync.Mutex
	entries map[string]*entry
	head    *entry // 最近使用
	tail    *entry // 最久未用

	enabled     atomic.Bool
	allowed     atomic.Uint64
	denied      atomic.Uint64
	evicted     atomic.Uint64
	bans        atomic.Uint64
	whitelisted atomic.Uint64
}

// New 构造限速器。
func New(o Options) (*Limiter, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.RPS > 0 && o.Burst <= 0 {
		o.Burst = o.RPS
	}
	if o.Burst < 1 {
		o.Burst = 1
	}
	if o.BanWindow <= 0 {
		o.BanWindow = time.Minute
	}
	if o.BanDuration <= 0 {
		o.BanDuration = 5 * time.Minute
	}
	if o.Capacity <= 0 {
		o.Capacity = 8192
	}
	l := &Limiter{o: o, entries: make(map[string]*entry, 1024)}
	for _, s := range o.Whitelist {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(s); err == nil {
			l.wl = append(l.wl, pfx.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			l.wl = append(l.wl, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		return nil, fmt.Errorf("ratelimit.whitelist 里的 %q 既不是 CIDR 也不是 IP", s)
	}
	l.enabled.Store(o.RPS > 0 || o.BanAfterHits > 0)
	return l, nil
}

// Enabled 报告限速是否生效。
func (l *Limiter) Enabled() bool { return l.enabled.Load() }

// Reconfigure 热改限速参数。
//
// 控制台改限速走这里。**不重建状态表**：已封禁的 IP 不会因为改了个 rps 就放出来，
// 已积累的违规计数也不清零 —— 否则攻击者只要诱导管理员改一次配置就能洗白。
func (l *Limiter) Reconfigure(o Options) error {
	if o.RPS < 0 {
		return fmt.Errorf("rps 不能为负")
	}
	if o.Burst <= 0 {
		o.Burst = o.RPS
	}
	if o.Burst < 1 {
		o.Burst = 1
	}
	if o.BanWindow <= 0 {
		o.BanWindow = time.Minute
	}
	if o.BanDuration <= 0 {
		o.BanDuration = 5 * time.Minute
	}
	var wl []netip.Prefix
	for _, s := range o.Whitelist {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(s); err == nil {
			wl = append(wl, pfx.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			wl = append(wl, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		return fmt.Errorf("whitelist 里的 %q 既不是 CIDR 也不是 IP", s)
	}

	l.mu.Lock()
	l.o.RPS = o.RPS
	l.o.Burst = o.Burst
	l.o.BanAfterHits = o.BanAfterHits
	l.o.BanWindow = o.BanWindow
	l.o.BanDuration = o.BanDuration
	l.wl = wl
	l.mu.Unlock()
	l.enabled.Store(o.RPS > 0 || o.BanAfterHits > 0)
	return nil
}

// Allow 判定一次请求。
//
// key 通常是已解析出的客户端 IP；控制台另用前缀区分（如 "console:1.2.3.4"）。
//
// 整个判定在一把锁里完成（含白名单检查）：这样热改参数（Reconfigure）
// 与判定之间不会出现"读到一半新一半旧"的状态。临界区里只有内存操作，很快。
func (l *Limiter) Allow(key string) Decision {
	if !l.enabled.Load() {
		return Decision{Allowed: true, Remaining: -1}
	}

	now := l.o.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.isWhitelistedLocked(key) {
		l.whitelisted.Add(1)
		return Decision{Allowed: true, Remaining: -1, Reason: "whitelist"}
	}

	e := l.get(key, now, true)
	if e == nil {
		// 表已满且淘汰失败（理论上不会发生）→ 放行。
		// 限速器出问题时**倾向于放行**：它不该成为可用性的单点。
		return Decision{Allowed: true, Remaining: -1, Reason: "store-full"}
	}

	if now.Before(e.bannedTo) {
		retry := e.bannedTo.Sub(now)
		l.denied.Add(1)
		return Decision{Allowed: false, Banned: true, RetryAfter: retry, Reason: "banned"}
	}

	// 令牌补充
	elapsed := now.Sub(e.last).Seconds()
	if elapsed > 0 {
		e.tokens += elapsed * l.o.RPS
		if e.tokens > l.o.Burst {
			e.tokens = l.o.Burst
		}
		e.last = now
	}

	if e.tokens >= 1 {
		e.tokens--
		remaining := int(e.tokens)
		l.allowed.Add(1)
		return Decision{Allowed: true, Remaining: remaining}
	}

	// 超限：这就是一次"违规"，计入封禁窗口
	l.recordViolationLocked(e, now)
	deniedNow := e.hits
	l.denied.Add(1)

	retryAfter := time.Duration(0)
	if l.o.RPS > 0 {
		retryAfter = time.Duration((1 - 0) / l.o.RPS * float64(time.Second))
	}
	_ = deniedNow
	return Decision{Allowed: false, RetryAfter: retryAfter, Reason: "rate-limit"}
}

// Penalize 记一次违规（如控制台认证失败），用于封禁计数。
//
// 与 Allow 分开是因为"认证失败"和"请求太频繁"是两种不同的违规，
// 但都该把同一个来源推向封禁。
func (l *Limiter) Penalize(key string) (banned bool, until time.Time) {
	now := l.o.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.o.BanAfterHits <= 0 {
		return false, time.Time{}
	}
	if l.isWhitelistedLocked(key) {
		return false, time.Time{}
	}
	e := l.get(key, now, true)
	if e == nil {
		return false, time.Time{}
	}
	if l.recordViolationLocked(e, now) {
		return true, e.bannedTo
	}
	return false, time.Time{}
}

// Ban 主动封禁一个 key。
func (l *Limiter) Ban(key string, d time.Duration) {
	if d <= 0 {
		d = l.o.BanDuration
	}
	now := l.o.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.get(key, now, true)
	if e == nil {
		return
	}
	e.bannedTo = now.Add(d)
	l.bans.Add(1)
}

// Unban 解除封禁。
func (l *Limiter) Unban(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.entries[key]; ok {
		e.bannedTo = time.Time{}
		e.hits = 0
	}
}

// BannedList 返回当前被封禁的 key（最多 limit 条），用于控制台展示。
func (l *Limiter) BannedList(limit int) []BanInfo {
	if limit <= 0 {
		limit = 100
	}
	now := l.o.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]BanInfo, 0, 16)
	for e := l.head; e != nil && len(out) < limit; e = e.next {
		if now.Before(e.bannedTo) {
			out = append(out, BanInfo{
				Key:       e.key,
				Until:     e.bannedTo,
				Remaining: e.bannedTo.Sub(now),
				Hits:      e.hits,
			})
		}
	}
	return out
}

// BanInfo 是一条封禁记录。
type BanInfo struct {
	Key       string
	Until     time.Time
	Remaining time.Duration
	Hits      int
}

// Stats 返回统计。
func (l *Limiter) Stats() Stats {
	now := l.o.Now()
	l.mu.Lock()
	keys, banned := len(l.entries), 0
	for _, e := range l.entries {
		if now.Before(e.bannedTo) {
			banned++
		}
	}
	l.mu.Unlock()
	return Stats{
		Keys:        keys,
		Banned:      banned,
		Allowed:     l.allowed.Load(),
		Denied:      l.denied.Load(),
		Evicted:     l.evicted.Load(),
		BansIssued:  l.bans.Load(),
		Whitelisted: l.whitelisted.Load(),
	}
}

// ---------------------------------------------------------------- 内部

// recordViolationLocked 记一次违规并在达到阈值时封禁。调用方必须持锁。
func (l *Limiter) recordViolationLocked(e *entry, now time.Time) bool {
	if l.o.BanAfterHits <= 0 {
		return false
	}
	if e.winStart.IsZero() || now.Sub(e.winStart) > l.o.BanWindow {
		e.winStart = now
		e.hits = 0
	}
	e.hits++
	if e.hits >= l.o.BanAfterHits {
		e.bannedTo = now.Add(l.o.BanDuration)
		e.hits = 0
		e.winStart = now
		l.bans.Add(1)
		return true
	}
	return false
}

// get 取或建一个 entry，并把它移到 LRU 头部。调用方必须持锁。
func (l *Limiter) get(key string, now time.Time, create bool) *entry {
	if e, ok := l.entries[key]; ok {
		// 封禁到期后顺手清理，避免"过期封禁"永久占着 key
		l.touch(e)
		return e
	}
	if !create {
		return nil
	}
	if len(l.entries) >= l.o.Capacity {
		l.evictLocked()
	}
	e := &entry{key: key, tokens: l.o.Burst, last: now, winStart: now}
	l.entries[key] = e
	l.pushFront(e)
	return e
}

func (l *Limiter) touch(e *entry) {
	if l.head == e {
		return
	}
	l.unlink(e)
	l.pushFront(e)
}

func (l *Limiter) pushFront(e *entry) {
	e.prev = nil
	e.next = l.head
	if l.head != nil {
		l.head.prev = e
	}
	l.head = e
	if l.tail == nil {
		l.tail = e
	}
}

func (l *Limiter) unlink(e *entry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if l.head == e {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if l.tail == e {
		l.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

func (l *Limiter) evictLocked() {
	victim := l.tail
	if victim == nil {
		return
	}
	// 只淘汰"没有还在生效的封禁"的条目：把封禁记录淘汰掉等于放走攻击者
	for victim != nil {
		if !l.o.Now().Before(victim.bannedTo) {
			break
		}
		victim = victim.prev
	}
	if victim == nil {
		// 全在封禁中：从最久未用的开始淘汰，保证有界（对封禁者影响可接受，
		// 因为封禁期间它们本来就被拒绝）
		victim = l.tail
	}
	l.unlink(victim)
	delete(l.entries, victim.key)
	l.evicted.Add(1)
}

// isWhitelistedLocked 判断是否在白名单内。**调用方必须持锁。**
func (l *Limiter) isWhitelistedLocked(key string) bool {
	if len(l.wl) == 0 {
		return false
	}
	ip := key
	if i := strings.LastIndexByte(key, ':'); i > 0 {
		// 允许 "console:1.2.3.4" 这种带前缀的 key
		if _, err := netip.ParseAddr(key[i+1:]); err == nil {
			ip = key[i+1:]
		} else if _, err := netip.ParseAddr(key[:i]); err == nil {
			ip = key[:i]
		}
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range l.wl {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Cleanup 清理过期条目（由后台定时调用，避免冷 key 长期占位）。
//
// 返回清理掉的条数。
func (l *Limiter) Cleanup(idle time.Duration) int {
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	now := l.o.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	removed := 0
	for e := l.tail; e != nil; {
		prev := e.prev
		if now.Sub(e.last) > idle && !now.Before(e.bannedTo) {
			l.unlink(e)
			delete(l.entries, e.key)
			removed++
		}
		e = prev
	}
	if removed > 0 {
		l.evicted.Add(uint64(removed))
	}
	return removed
}

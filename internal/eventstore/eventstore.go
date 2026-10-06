// Package eventstore 保存检测事件的近期历史，供控制台与 CLI 查询。
//
// 存储形态（docs/CONSOLE.md §7）：
//   - **内存 ring buffer**：最近的 N 条完整事件（N 来自档位预算，medium 档 512 条）。
//     控制台列表与详情只查这里 —— 2C2G 上"翻全量历史"是最先翻车的地方。
//   - **分钟聚合桶**：1440 个（24 小时），只存计数与分布，用于画曲线。
//     桶是定长数组，不随流量增长。
//
// 明确不做的事：
//   - 不引外部时序库（InfluxDB/ES）。低配机器上多一个进程就是多一份内存与运维面。
//   - 不在这里做持久化。落盘由审计日志负责（按天 JSONL + 轮转 + 磁盘水位），
//     本包只管"最近发生了什么"。
//
// 关于 payload：**日志里绝不写 payload 原文，但内存事件里会留一份可打印化的副本**。
// 这不是自相矛盾 —— 日志是长期落盘、可能被同步到别处、可能被多人翻看的东西；
// 内存事件是控制台用来给人看"到底命中了什么"的，重启即失。
// 副本有硬上限（每条 4 KiB，可打印化），不会因为一个 10 MB 的 body 把内存撑爆。
package eventstore

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event 是一条检测事件。
type Event struct {
	ID       string    `json:"id"`
	Ts       time.Time `json:"ts"`
	TxID     string    `json:"tx_id"`
	ClientIP string    `json:"client_ip"`
	Method   string    `json:"method"`
	Host     string    `json:"host"`
	Path     string    `json:"path"`
	Proto    string    `json:"proto"`
	Status   int       `json:"status"`
	Verdict  string    `json:"verdict"`
	Score    int       `json:"score"`
	Ruleset  string    `json:"ruleset"`
	Mode     string    `json:"mode"`

	// 命中信息（可能有多条规则，这里存"主导"的那一条 + 全部命中 ID 列表）
	RuleID     string   `json:"rule_id,omitempty"`
	Category   string   `json:"category,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Message    string   `json:"message,omitempty"`
	Target     string   `json:"target,omitempty"`
	Operator   string   `json:"operator,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	MatchedLen int      `json:"matched_len,omitempty"`
	Hits       []HitRef `json:"hits,omitempty"`

	// 上游与来源
	UserAgent  string   `json:"user_agent,omitempty"`
	Referer    string   `json:"referer,omitempty"`
	ProxyChain []string `json:"proxy_chain,omitempty"`
	UpstreamMs float64  `json:"upstream_ms,omitempty"`
	TotalMs    float64  `json:"total_ms,omitempty"`

	// payload 的可打印化副本（变换前 / 变换后）。绝对代码模式展示用。
	PayloadBefore    string `json:"payload_before,omitempty"`
	PayloadAfter     string `json:"payload_after,omitempty"`
	PayloadTruncated bool   `json:"payload_truncated,omitempty"`
}

// HitRef 是事件里的一条命中摘要。
type HitRef struct {
	RuleID   string `json:"rule_id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	Score    int    `json:"score"`
}

// Options 是存储构造参数。
type Options struct {
	// RingSize 是内存里保留的完整事件条数上限。
	RingSize int
	// PayloadLimit 是单条 payload 副本的字节上限。
	PayloadLimit int
	// Now 时间源，测试注入。
	Now func() time.Time
}

// DefaultOptions 返回与 medium 档匹配的默认值。
func DefaultOptions() Options {
	return Options{RingSize: 512, PayloadLimit: 4 << 10}
}

// Store 是事件存储。可并发使用。
type Store struct {
	o Options

	mu   sync.RWMutex
	ring []Event
	head int // 下一个写入位置
	size int

	// 分钟聚合桶：索引 = (unix分钟) % 1440
	buckets [1440]bucket
	lastMin int64

	// 全量计数（不随 ring 淘汰而减少）
	total      atomic.Uint64
	byVerdict  sync.Map // string -> *atomic.Uint64
	byCategory sync.Map
	bySeverity sync.Map
	banned     atomic.Uint64
	blocked    atomic.Uint64

	// 时间序列缓存（最近 24h 的每分钟计数）
	seqTotal   [1440]uint32
	seqBlocked [1440]uint32

	// 订阅者（SSE 实时流用）。容量有界：控制台最多几个标签页在看。
	subMu   sync.Mutex
	subs    map[int]chan Event
	nextSub int
}

// maxSubscribers 限制同时订阅数。**必须有界** —— 订阅者各自持有一个 channel，
// 无限订阅就是内存泄漏。
const maxSubscribers = 8

type bucket struct {
	minute  int64
	total   uint32
	blocked uint32
}

// New 构造存储。
func New(o Options) *Store {
	if o.RingSize <= 0 {
		o.RingSize = 512
	}
	if o.PayloadLimit <= 0 {
		o.PayloadLimit = 4 << 10
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Store{o: o, ring: make([]Event, o.RingSize), subs: map[int]chan Event{}}
}

// Len 返回当前保留的事件条数。
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.size
}

// Total 返回自启动以来的事件总数（不受 ring 淘汰影响）。
func (s *Store) Total() uint64 { return s.total.Load() }

// Add 写入一条事件。
//
// 这里做 payload 的可打印化截断：**在入口处做一次**，而不是每次展示时做 ——
// 否则控制台一刷新就要重新处理一遍所有事件。
func (s *Store) Add(e Event) {
	if e.ID == "" {
		e.ID = e.TxID
	}
	if e.ID == "" {
		e.ID = strconv.FormatInt(e.Ts.UnixNano(), 36)
	}
	if e.Ts.IsZero() {
		e.Ts = s.o.Now()
	}
	if e.PayloadBefore != "" {
		e.PayloadBefore, e.PayloadTruncated = clipPrintable(e.PayloadBefore, s.o.PayloadLimit)
	}
	if e.PayloadAfter != "" {
		var t bool
		e.PayloadAfter, t = clipPrintable(e.PayloadAfter, s.o.PayloadLimit)
		e.PayloadTruncated = e.PayloadTruncated || t
	}

	minute := e.Ts.Unix() / 60
	s.mu.Lock()
	s.ring[s.head] = e
	s.head = (s.head + 1) % len(s.ring)
	if s.size < len(s.ring) {
		s.size++
	}
	idx := int(((minute % 1440) + 1440) % 1440)
	if s.buckets[idx].minute != minute {
		s.buckets[idx] = bucket{minute: minute}
		s.seqTotal[idx] = 0
		s.seqBlocked[idx] = 0
	}
	s.buckets[idx].total++
	s.seqTotal[idx]++
	if isBlocking(e.Verdict) {
		s.buckets[idx].blocked++
		s.seqBlocked[idx]++
	}
	s.lastMin = minute
	s.mu.Unlock()

	s.total.Add(1)
	incr(&s.byVerdict, e.Verdict)
	if e.Category != "" {
		incr(&s.byCategory, e.Category)
	}
	if e.Severity != "" {
		incr(&s.bySeverity, e.Severity)
	}
	if isBlocking(e.Verdict) {
		s.blocked.Add(1)
	}
	s.publish(e)
}

// Subscribe 订阅新事件。返回的 channel 有缓冲，**发布者永不阻塞**：
// 订阅者跟不上就丢事件（实时流丢几条远比卡住数据面可接受）。
func (s *Store) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	s.subMu.Lock()
	if len(s.subs) >= maxSubscribers {
		s.subMu.Unlock()
		close(ch)
		return ch, func() {}
	}
	id := s.nextSub
	s.nextSub++
	s.subs[id] = ch
	s.subMu.Unlock()
	cancel := func() {
		s.subMu.Lock()
		if c, ok := s.subs[id]; ok {
			delete(s.subs, id)
			close(c)
		}
		s.subMu.Unlock()
	}
	return ch, cancel
}

func (s *Store) publish(e Event) {
	s.subMu.Lock()
	for _, ch := range s.subs {
		select {
		case ch <- e:
		default: // 订阅者跟不上：丢这一条，绝不阻塞数据面
		}
	}
	s.subMu.Unlock()
}

// Subscribers 返回当前订阅者数量（排查连接泄漏用）。
func (s *Store) Subscribers() int {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	return len(s.subs)
}

// Get 按 ID 取事件。
func (s *Store) Get(id string) (Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// 从最新往旧找（控制台通常看刚发生的）
	for i := 0; i < s.size; i++ {
		idx := (s.head - 1 - i + len(s.ring)) % len(s.ring)
		if s.ring[idx].ID == id || s.ring[idx].TxID == id {
			return s.ring[idx], true
		}
	}
	return Event{}, false
}

// Query 是列表查询条件。
type Query struct {
	// Cursor 是上一页最后一条的 ID（不含）；空表示从头（最新）开始。
	Cursor   string
	Limit    int
	Verdict  string
	Category string
	Severity string
	ClientIP string
	RuleID   string
	// PathContains 是路径子串匹配（不做正则：控制台里输入的应当是子串）。
	PathContains string
	// Search 在路径、规则 ID、明细、类目里做子串匹配。
	Search string
	Since  time.Time
	Until  time.Time
	// OnlyBlocked 只返回被拦截的事件。
	OnlyBlocked bool
}

// List 返回事件列表（最新在前）与下一页游标。
func (s *Store) List(q Query) ([]Event, string) {
	if q.Limit <= 0 {
		q.Limit = 50
	}
	if q.Limit > 500 {
		q.Limit = 500
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Event, 0, q.Limit)
	skipping := q.Cursor != ""
	next := ""
	for i := 0; i < s.size; i++ {
		idx := (s.head - 1 - i + len(s.ring)) % len(s.ring)
		e := s.ring[idx]
		if skipping {
			if e.ID == q.Cursor {
				skipping = false
			}
			continue
		}
		if !matchQuery(e, q) {
			continue
		}
		if len(out) >= q.Limit {
			next = out[len(out)-1].ID
			break
		}
		out = append(out, e)
	}
	return out, next
}

func matchQuery(e Event, q Query) bool {
	if q.Verdict != "" && !strings.EqualFold(e.Verdict, q.Verdict) {
		return false
	}
	if q.Category != "" && !strings.EqualFold(e.Category, q.Category) {
		return false
	}
	if q.Severity != "" && !strings.EqualFold(e.Severity, q.Severity) {
		return false
	}
	if q.ClientIP != "" && e.ClientIP != q.ClientIP {
		return false
	}
	if q.RuleID != "" && !strings.EqualFold(e.RuleID, q.RuleID) {
		return false
	}
	if q.PathContains != "" && !strings.Contains(e.Path, q.PathContains) {
		return false
	}
	if q.OnlyBlocked && !isBlocking(e.Verdict) {
		return false
	}
	if !q.Since.IsZero() && e.Ts.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && e.Ts.After(q.Until) {
		return false
	}
	if q.Search != "" {
		needle := strings.ToLower(q.Search)
		hay := strings.ToLower(e.Path + " " + e.RuleID + " " + e.Category + " " + e.Detail + " " + e.ClientIP + " " + e.Target)
		if !strings.Contains(hay, needle) {
			return false
		}
	}
	return true
}

// Summary 是概览统计。
type Summary struct {
	Total      uint64            `json:"total"`
	Retained   int               `json:"retained"`
	Blocked    uint64            `json:"blocked"`
	ByVerdict  map[string]uint64 `json:"by_verdict"`
	ByCategory map[string]uint64 `json:"by_category"`
	BySeverity map[string]uint64 `json:"by_severity"`
	Window     string            `json:"window"`
	RingSize   int               `json:"ring_size"`
}

// Summary 返回统计快照。
func (s *Store) Summary() Summary {
	return Summary{
		Total:      s.total.Load(),
		Retained:   s.Len(),
		Blocked:    s.blocked.Load(),
		ByVerdict:  drain(&s.byVerdict),
		ByCategory: drain(&s.byCategory),
		BySeverity: drain(&s.bySeverity),
		RingSize:   s.o.RingSize,
	}
}

// Point 是时间序列上的一个点。
type Point struct {
	Ts      time.Time `json:"ts"`
	Total   uint32    `json:"total"`
	Blocked uint32    `json:"blocked"`
}

// Timeseries 返回最近 minutes 分钟的时间序列（不足的分钟补 0）。
func (s *Store) Timeseries(minutes int) []Point {
	if minutes <= 0 || minutes > 1440 {
		minutes = 60
	}
	now := s.o.Now().Unix() / 60
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Point, 0, minutes)
	for i := minutes - 1; i >= 0; i-- {
		m := now - int64(i)
		idx := int(((m % 1440) + 1440) % 1440)
		p := Point{Ts: time.Unix(m*60, 0)}
		if s.buckets[idx].minute == m {
			p.Total = s.buckets[idx].total
			p.Blocked = s.buckets[idx].blocked
		}
		out = append(out, p)
	}
	return out
}

// Categories 返回按数量倒序的类目分布。
func (s *Store) Categories() []Count {
	m := drain(&s.byCategory)
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Key: k, N: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// Count 是一个"键 → 计数"。
type Count struct {
	Key string `json:"key"`
	N   uint64 `json:"n"`
}

// TopIPs 返回命中最多的来源 IP（从 ring 里统计，不需要额外索引）。
func (s *Store) TopIPs(limit int) []Count {
	if limit <= 0 {
		limit = 10
	}
	s.mu.RLock()
	counts := map[string]uint64{}
	for i := 0; i < s.size; i++ {
		idx := (s.head - 1 - i + len(s.ring)) % len(s.ring)
		e := s.ring[idx]
		if e.ClientIP != "" && isBlocking(e.Verdict) {
			counts[e.ClientIP]++
		}
	}
	s.mu.RUnlock()

	out := make([]Count, 0, len(counts))
	for k, v := range counts {
		out = append(out, Count{Key: k, N: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Clear 清空内存事件（控制台里的"清空视图"用；不影响落盘日志）。
func (s *Store) Clear() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.size
	for i := range s.ring {
		s.ring[i] = Event{}
	}
	s.head, s.size = 0, 0
	return n
}

// ---------------------------------------------------------------- 工具

func isBlocking(verdict string) bool {
	switch verdict {
	case "block", "drop", "tarpit", "challenge", "ratelimit", "rejected_degraded", "banned":
		return true
	}
	return false
}

func incr(m *sync.Map, key string) {
	if key == "" {
		return
	}
	v, ok := m.Load(key)
	if !ok {
		v, _ = m.LoadOrStore(key, &atomic.Uint64{})
	}
	v.(*atomic.Uint64).Add(1)
}

func drain(m *sync.Map) map[string]uint64 {
	out := map[string]uint64{}
	m.Range(func(k, v any) bool {
		out[k.(string)] = v.(*atomic.Uint64).Load()
		return true
	})
	return out
}

// clipPrintable 把字节转成可打印形式并截断。
//
// 可打印化规则（docs/CONSOLE.md §3.4）：可打印 ASCII 原样，其余转 \xNN；
// 截断时**保证不切碎 UTF-8 字符**（否则前端拿到的最后一个字符是乱码方块）。
func clipPrintable(s string, limit int) (string, bool) {
	var sb strings.Builder
	sb.Grow(len(s) + 16)
	truncated := false
	for i := 0; i < len(s); i++ {
		if sb.Len() >= limit {
			truncated = true
			break
		}
		c := s[i]
		switch {
		case c == '\n':
			sb.WriteString("\\n")
		case c == '\r':
			sb.WriteString("\\r")
		case c == '\t':
			sb.WriteString("\\t")
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		case c >= 0x80:
			// 多字节：按 UTF-8 边界整体复制，别切碎
			r, size := decodeRune(s[i:])
			if r == 0 {
				fmt.Fprintf(&sb, "\\x%02x", c)
				continue
			}
			if sb.Len()+size > limit {
				truncated = true
				i = len(s)
				break
			}
			sb.WriteString(s[i : i+size])
			i += size - 1
		default:
			fmt.Fprintf(&sb, "\\x%02x", c)
		}
	}
	return sb.String(), truncated
}

// decodeRune 返回下一个完整 UTF-8 字符及其字节数；非法序列返回 false。
func decodeRune(s string) (rune, int) {
	c := s[0]
	switch {
	case c < 0x80:
		return rune(c), 1
	case c&0xE0 == 0xC0:
		if len(s) < 2 || s[1]&0xC0 != 0x80 {
			return 0, 0
		}
		return rune(c&0x1F)<<6 | rune(s[1]&0x3F), 2
	case c&0xF0 == 0xE0:
		if len(s) < 3 || s[1]&0xC0 != 0x80 || s[2]&0xC0 != 0x80 {
			return 0, 0
		}
		return rune(c&0x0F)<<12 | rune(s[1]&0x3F)<<6 | rune(s[2]&0x3F), 3
	case c&0xF8 == 0xF0:
		if len(s) < 4 || s[1]&0xC0 != 0x80 || s[2]&0xC0 != 0x80 || s[3]&0xC0 != 0x80 {
			return 0, 0
		}
		return rune(c&0x07)<<18 | rune(s[1]&0x3F)<<12 | rune(s[2]&0x3F)<<6 | rune(s[3]&0x3F), 4
	default:
		return 0, 0
	}
}

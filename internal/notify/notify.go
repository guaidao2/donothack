// Package notify 把"值得人看的事件"推到外部通道（webhook）。
//
// 三条纪律（都是从"告警系统本身变成故障源"这个方向倒推的）：
//
//  1. **绝不阻塞数据面**：发送在独立 goroutine 里做，队列有界，满了就丢并计数。
//     告警通道挂了不能让业务跟着挂 —— 这与日志的取舍完全一致。
//  2. **必须限流**：一次扫描能在几秒内打出上万个事件。不加限流的话，
//     首选结果是"把对方的 webhook 打挂"，其次才是"你自己的带宽被打满"。
//     所以按类型做冷却时间，同一类告警在冷却期内只发一条（并带聚合计数）。
//  3. **不发送 payload 原文**：告警常被转到 IM、邮件、工单系统，
//     那些地方的访问控制通常比 WAF 本身弱得多。只发类目、目标名、请求 ID 与计数。
//
// webhook 体是 JSON，字段刻意精简；接收方（IM 机器人、工单系统）都能直接解析。
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Event 是一条告警。
type Event struct {
	Kind     string    `json:"kind"` // block | ratelimit | ban | degrade | engine_error
	At       time.Time `json:"at"`
	Severity string    `json:"severity,omitempty"`
	Category string    `json:"category,omitempty"`
	RuleID   string    `json:"rule_id,omitempty"`
	Target   string    `json:"target,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Method   string    `json:"method,omitempty"`
	Path     string    `json:"path,omitempty"`
	ClientIP string    `json:"client_ip,omitempty"`
	TxID     string    `json:"tx_id,omitempty"`
	Verdict  string    `json:"verdict,omitempty"`
	Score    int       `json:"score,omitempty"`
	// Count 是"冷却期内被合并的次数"：同一条告警发出去时带上它，
	// 避免收件人以为"只发生了一次"。
	Count uint64 `json:"count,omitempty"`
	// Instance 是实例标识（多实例部署时区分来源）。
	Instance string `json:"instance,omitempty"`
}

// Options 是构造参数。
type Options struct {
	Enabled  bool
	Webhook  string
	Timeout  time.Duration
	QueueCap int
	// Cooldown 是同一 kind+category 的最小发送间隔。
	Cooldown time.Duration
	// MinSeverity 是发送门槛（info/low/medium/high/critical）。
	MinSeverity string
	Instance    string
	// Now 时间源，测试注入。
	Now func() time.Time
	// Client 可注入（测试用）。
	Client *http.Client
}

// Stats 是告警通道统计。
type Stats struct {
	Enabled    bool   `json:"enabled"`
	Queued     uint64 `json:"queued"`
	Sent       uint64 `json:"sent"`
	Failed     uint64 `json:"failed"`
	Dropped    uint64 `json:"dropped"`
	Suppressed uint64 `json:"suppressed"`
	LastError  string `json:"last_error,omitempty"`
	LastSentAt string `json:"last_sent_at,omitempty"`
	QueueLen   int    `json:"queue_len"`
	QueueCap   int    `json:"queue_cap"`
}

// Notifier 是告警发送器。
type Notifier struct {
	o Options

	ch   chan Event
	stop chan struct{}
	once sync.Once
	wg   sync.WaitGroup

	mu        sync.Mutex
	cool      map[string]time.Time
	coolCount map[string]uint64
	lastErr   string
	lastSent  time.Time

	queued     atomic.Uint64
	sent       atomic.Uint64
	failed     atomic.Uint64
	dropped    atomic.Uint64
	suppressed atomic.Uint64
}

// New 构造发送器。webhook 为空或未启用时返回一个"什么都不做"的实例，
// 调用方不需要在热路径上判断 nil。
func New(o Options) *Notifier {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.QueueCap <= 0 {
		o.QueueCap = 256
	}
	// Cooldown == 0 用默认值；**负值表示关闭冷却**。
	// 为什么要有"关闭"这个显式语义：把冷却设成极小值（如 1ns）在 Windows 上
	// 会因为系统时钟粒度（约 15ms）变成"同一刻的所有告警互相抑制" ——
	// 那是靠不住的，想要不抑制就该明说。
	if o.Cooldown == 0 {
		o.Cooldown = 30 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: o.Timeout}
	}
	n := &Notifier{
		o:         o,
		stop:      make(chan struct{}),
		cool:      map[string]time.Time{},
		coolCount: map[string]uint64{},
	}
	if !n.enabled() {
		return n
	}
	n.ch = make(chan Event, o.QueueCap)
	n.wg.Add(1)
	go n.loop()
	return n
}

func (n *Notifier) enabled() bool {
	return n.o.Enabled && strings.TrimSpace(n.o.Webhook) != ""
}

// Enabled 报告告警是否生效。
func (n *Notifier) Enabled() bool { return n.enabled() }

// Notify 提交一条告警。**永不阻塞**：队列满就丢并计数。
func (n *Notifier) Notify(e Event) {
	if !n.enabled() {
		return
	}
	if !n.severityOK(e.Severity) {
		return
	}
	if e.At.IsZero() {
		e.At = n.o.Now()
	}
	if e.Instance == "" {
		e.Instance = n.o.Instance
	}

	// 冷却：同一 kind+category 在冷却期内只发一条，计数累加。
	key := e.Kind + "|" + e.Category + "|" + e.RuleID
	n.mu.Lock()
	if last, ok := n.cool[key]; ok && n.o.Cooldown > 0 && e.At.Sub(last) < n.o.Cooldown {
		n.coolCount[key]++
		n.mu.Unlock()
		n.suppressed.Add(1)
		return
	}
	count := n.coolCount[key] + 1
	n.coolCount[key] = 0
	n.cool[key] = e.At
	// 冷却表本身也要有界：key 来自 kind+category+ruleID，数量有限（规则数是固定的）。
	if len(n.cool) > 4096 {
		n.cool = map[string]time.Time{}
	}
	n.mu.Unlock()
	e.Count = count

	n.queued.Add(1)
	select {
	case n.ch <- e:
	default:
		// 队列满：丢掉并计数。绝不在这里阻塞数据面。
		n.dropped.Add(1)
	}
}

// Send 同步发一条（供 /notify/test 用，不走冷却与队列）。
func (n *Notifier) Send(ctx context.Context, e Event) error {
	if !n.enabled() {
		return fmt.Errorf("告警未启用或未配置 webhook")
	}
	if e.At.IsZero() {
		e.At = n.o.Now()
	}
	if e.Instance == "" {
		e.Instance = n.o.Instance
	}
	return n.post(ctx, e)
}

func (n *Notifier) loop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.stop:
			// 退出前把队列里剩下的尽量发完（有上限，不会卡住）
			for {
				select {
				case e := <-n.ch:
					_ = n.post(context.Background(), e)
				default:
					return
				}
			}
		case e := <-n.ch:
			ctx, cancel := context.WithTimeout(context.Background(), n.o.Timeout)
			err := n.post(ctx, e)
			cancel()
			if err != nil {
				n.failed.Add(1)
				n.mu.Lock()
				n.lastErr = err.Error()
				n.mu.Unlock()
			} else {
				n.sent.Add(1)
				n.mu.Lock()
				n.lastSent = n.o.Now()
				n.lastErr = ""
				n.mu.Unlock()
			}
		}
	}
}

func (n *Notifier) post(ctx context.Context, e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.o.Webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "donothack-notify")
	resp, err := n.o.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook 返回 %d", resp.StatusCode)
	}
	return nil
}

// severityOK 判断严重度是否达到发送门槛。
func (n *Notifier) severityOK(sev string) bool {
	min := strings.ToLower(strings.TrimSpace(n.o.MinSeverity))
	if min == "" {
		return true
	}
	rank := func(s string) int {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "critical":
			return 4
		case "high":
			return 3
		case "medium":
			return 2
		case "low":
			return 1
		default:
			return 0
		}
	}
	return rank(sev) >= rank(min)
}

// Stats 返回统计。
func (n *Notifier) Stats() Stats {
	st := Stats{
		Enabled:    n.enabled(),
		Queued:     n.queued.Load(),
		Sent:       n.sent.Load(),
		Failed:     n.failed.Load(),
		Dropped:    n.dropped.Load(),
		Suppressed: n.suppressed.Load(),
		QueueCap:   n.o.QueueCap,
	}
	if n.ch != nil {
		st.QueueLen = len(n.ch)
	}
	n.mu.Lock()
	st.LastError = n.lastErr
	if !n.lastSent.IsZero() {
		st.LastSentAt = n.lastSent.Format(time.RFC3339)
	}
	n.mu.Unlock()
	return st
}

// Close 停止发送器（尽量把队列发完再退出）。
func (n *Notifier) Close() {
	if n.ch == nil {
		return
	}
	n.once.Do(func() {
		close(n.stop)
		n.wg.Wait()
	})
}

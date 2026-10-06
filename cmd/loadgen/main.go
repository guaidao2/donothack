// Command loadgen 是一个极简 HTTP 压测器，专供本项目的性能门禁使用。
//
// 为什么不直接用 hey/wrk：那两者都要额外安装，而本项目要求"低配机器上也能跑出基线"。
// 这个工具只用标准库，交叉编译后丢到目标机器上就能出数。
//
// 用法：
//
//	loadgen -url http://127.0.0.1:8080/ -c 32 -d 10s
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	var (
		url        = flag.String("url", "http://127.0.0.1:8080/", "压测目标")
		concur     = flag.Int("c", 32, "并发数")
		duration   = durationFlag("d", 10*time.Second, "持续时间（可写 8 或 8s；裸数字按秒算）")
		timeout    = flag.Duration("timeout", 10*time.Second, "单请求超时")
		method     = flag.String("method", "GET", "请求方法")
		bodyBytes  = flag.Int("bodysize", 0, "请求体大小（字节，0 表示无 body）")
		label      = flag.String("label", "", "输出标签（例如 baseline / through-waf）")
		warmup     = flag.Duration("warmup", 2*time.Second, "预热时长（不计入统计）")
		maxSamples = flag.Int("maxsamples", 2_000_000, "最多采样数（防止内存无界）")
	)
	flag.Parse()

	if *concur <= 0 {
		fatal("并发数必须为正")
	}

	body := make([]byte, *bodyBytes)
	for i := range body {
		body[i] = 'a'
	}

	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        *concur * 2,
		MaxIdleConnsPerHost: *concur,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}
	client := &http.Client{Transport: tr, Timeout: *timeout}

	if *warmup > 0 {
		run(context.Background(), client, *url, *method, body, *concur, *warmup, 0)
	}

	start := time.Now()
	stats := run(context.Background(), client, *url, *method, body, *concur, *duration, *maxSamples)
	elapsed := time.Since(start)

	report(*label, *url, *concur, *duration, elapsed, stats, body)
}

type stats struct {
	mu       sync.Mutex
	latency  []time.Duration
	ok       int64
	non2xx   int64
	errors   int64
	errFirst string
	samples  int
}

func run(ctx context.Context, client *http.Client, url, method string, body []byte, concur int, dur time.Duration, maxSamples int) *stats {
	ctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	s := &stats{}
	var wg sync.WaitGroup
	perWorker := maxSamples / max(concur, 1)

	for i := 0; i < concur; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 4096)
			for ctx.Err() == nil {
				var rdr io.Reader
				if len(body) > 0 {
					rdr = newBytesReader(body)
				}
				req, err := http.NewRequestWithContext(ctx, method, url, rdr)
				if err != nil {
					s.recordErr(err)
					return
				}
				req.Close = false
				t0 := time.Now()
				resp, err := client.Do(req)
				d := time.Since(t0)
				if err != nil {
					if ctx.Err() != nil {
						break
					}
					s.recordErr(err)
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				_ = n
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					s.recordNon2xx()
					continue
				}
				if len(local) < perWorker {
					local = append(local, d)
				}
			}
			s.merge(local)
		}()
	}
	wg.Wait()
	return s
}

func (s *stats) recordErr(err error) {
	s.mu.Lock()
	s.errors++
	if s.errFirst == "" {
		s.errFirst = err.Error()
	}
	s.mu.Unlock()
}

func (s *stats) recordNon2xx() {
	s.mu.Lock()
	s.non2xx++
	s.mu.Unlock()
}

func (s *stats) merge(local []time.Duration) {
	s.mu.Lock()
	s.latency = append(s.latency, local...)
	s.samples += len(local)
	s.mu.Unlock()
}

type bytesReader struct {
	b []byte
	i int
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{b: b} }

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.i >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.i:])
	r.i += n
	return n, nil
}

func report(label, url string, concur int, dur, elapsed time.Duration, s *stats, body []byte) {
	s.mu.Lock()
	lat := s.latency
	ok, non2xx, errs, errFirst := int64(len(lat)), s.non2xx, s.errors, s.errFirst
	s.mu.Unlock()

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })

	total := ok + non2xx + errs
	rps := float64(ok) / elapsed.Seconds()

	fmt.Printf("=== loadgen 结果 ===\n")
	if label != "" {
		fmt.Printf("标签        : %s\n", label)
	}
	fmt.Printf("目标        : %s\n", url)
	fmt.Printf("并发/时长   : %d / %s（实际 %.2fs）\n", concur, dur, elapsed.Seconds())
	fmt.Printf("请求体      : %d 字节\n", len(body))
	fmt.Printf("总请求      : %d\n", total)
	fmt.Printf("成功 2xx    : %d\n", ok)
	fmt.Printf("非 2xx      : %d\n", non2xx)
	fmt.Printf("错误        : %d\n", errs)
	if errFirst != "" {
		fmt.Printf("首个错误    : %s\n", errFirst)
	}
	fmt.Printf("RPS(成功)   : %.1f\n", rps)
	if len(lat) > 0 {
		fmt.Printf("延迟 p50    : %s\n", pct(lat, 0.50))
		fmt.Printf("延迟 p90    : %s\n", pct(lat, 0.90))
		fmt.Printf("延迟 p99    : %s\n", pct(lat, 0.99))
		fmt.Printf("延迟 max    : %s\n", lat[len(lat)-1])
	}
}

func pct(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "loadgen: "+msg)
	os.Exit(1)
}

// durationFlag 让 `-d 8` 与 `-d 8s` 都能用。
//
// 为什么较真：脚本与手工命令都写过裸数字，而 flag.Duration 只认 "8s"。
// 结果压测静默跑出 0 RPS —— **一个不会失败的基准比没有基准更糟**，
// 所以这里既让它容错，也在 bench.py 侧加了"0 RPS 直接失败"的判据。
func durationFlag(name string, def time.Duration, usage string) *time.Duration {
	return durationValue(name, def, usage)
}

type durationVal struct{ v *time.Duration }

func (d durationVal) String() string {
	if d.v == nil {
		return ""
	}
	return d.v.String()
}

func (d durationVal) Set(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("持续时间不能为空")
	}
	// 纯数字 → 按秒
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 {
			return fmt.Errorf("持续时间必须为正")
		}
		*d.v = time.Duration(n) * time.Second
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("无法解析持续时间 %q（示例：8 或 8s 或 500ms）", s)
	}
	if parsed <= 0 {
		return fmt.Errorf("持续时间必须为正")
	}
	*d.v = parsed
	return nil
}

func durationValue(name string, def time.Duration, usage string) *time.Duration {
	v := new(time.Duration)
	*v = def
	flag.Var(durationVal{v: v}, name, usage)
	return v
}

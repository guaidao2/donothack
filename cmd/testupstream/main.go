// Command testupstream 是性能测试用的假上游：固定状态码、固定大小响应体。
//
// 它存在的意义是让压测不依赖外部服务：docs/PERFORMANCE.md §10.2 要求
// "起 httptest 假上游 → 起 donothack → 分别压直连与经过 WAF"，
// 这个二进制就是那个假上游的进程形态。
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		addr    = flag.String("addr", "127.0.0.1:9000", "监听地址")
		size    = flag.Int("size", 1024, "响应体大小（字节）")
		status  = flag.Int("status", 200, "响应状态码")
		delay   = flag.Duration("delay", 0, "人为延迟（用于测试并发连接上限）")
		echoHdr = flag.Bool("echo-header", false, "把收到的 X-Request-ID 回显在响应头里")
	)
	flag.Parse()

	body := strings.Repeat("x", *size)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *delay > 0 {
			time.Sleep(*delay)
		}
		if *echoHdr {
			w.Header().Set("X-Request-ID", r.Header.Get("X-Request-ID"))
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Server", "testupstream")
		w.WriteHeader(*status)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(body))
		}
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	fmt.Fprintf(os.Stdout, "testupstream 监听 %s（status=%d size=%d delay=%s）\n", *addr, *status, *size, *delay)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("testupstream: %v", err)
	}
}

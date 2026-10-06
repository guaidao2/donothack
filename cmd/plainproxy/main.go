// Command plainproxy 是一个**不做任何检测**的裸反向代理，仅用作性能基线。
//
// 为什么需要它：把"直连上游"当成基线是不公平的 —— 直连是一跳 HTTP，
// 而经过 WAF 是两跳。同一台机器上两跳的吞吐天然接近腰斩，那个差值量的是
// "多了一跳代理"，不是"WAF 慢"。
//
// 公平基线是"同样的反向代理、同样的 Transport 调优，但不做检测"。
// donothack 与它的差值，才是我们自己的开销。
//
// 这个二进制只用于压测，不随发布产物分发。
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func main() {
	var (
		addr          = flag.String("addr", "127.0.0.1:18081", "监听地址")
		upstream      = flag.String("upstream", "http://127.0.0.1:19000", "上游地址")
		maxIdlePerHst = flag.Int("max-idle-per-host", 64, "上游每主机空闲连接数")
	)
	flag.Parse()

	target, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("plainproxy: 上游地址无效：%v", err)
	}

	tr := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          max(2, *maxIdlePerHst*2),
		MaxIdleConnsPerHost:   *maxIdlePerHst,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
	}

	rp := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
		},
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           rp,
		MaxHeaderBytes:    32 << 10,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("plainproxy 监听 %s → %s", *addr, *upstream)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("plainproxy: %v", err)
	}
}

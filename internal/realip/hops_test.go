package realip

import (
	"net/http"
	"strings"
	"testing"
)

// 的回归测试：XFF 超过 maxHops 时，必须保留**最右**（最近一跳）。
//
// 旧实现是 `parts[:maxHops]`，保留最左、丢掉最右 —— 攻击者塞满 32 项就能把
// 负载均衡器追加的真实 IP 挤掉，判定从他自己写的那一项开始，于是
// "每个请求自称任意 IP"（限速/封禁/审计 IP 一起失效）。
func TestForwardedChainKeepsNearestHops(t *testing.T) {
	// 可信代理：负载均衡器
	r, err := New(Options{
		Header:         "X-Forwarded-For",
		TrustedProxies: []string{"10.0.0.0/8"},
		MaxHops:        4,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 攻击者填 6 项垃圾（从 1.1.1.1 起），最后是 LB 追加的真实客户端 203.0.113.7
	xff := strings.Join([]string{
		"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6",
		"203.0.113.7",
	}, ", ")

	h := http.Header{}
	h.Set("X-Forwarded-For", xff)
	res := r.Resolve("10.0.0.9:1234", h) // 对端是可信 LB

	if res.IP != "203.0.113.7" {
		t.Fatalf("应当取最近一跳的真实客户端 203.0.113.7，实际 %q（截断方向反了就会取到攻击者伪造的地址）", res.IP)
	}
}

// 攻击者伪造的地址不能被当作客户端：整条链里没有不可信对端时，取链尾。
func TestSpoofedEntriesAreNotUsedWhenTruncated(t *testing.T) {
	r, err := New(Options{
		Header:         "X-Forwarded-For",
		TrustedProxies: []string{"10.0.0.0/8"},
		MaxHops:        3,
	})
	if err != nil {
		t.Fatal(err)
	}
	// 全是可以被攻击者控制的公网地址 + 末尾一个可信代理
	h := http.Header{}
	h.Set("X-Forwarded-For", "6.6.6.6, 7.7.7.7, 8.8.8.8, 10.0.0.5")
	res := r.Resolve("10.0.0.9:1234", h)
	// 从右往左：10.0.0.5 可信 → 继续；8.8.8.8 不可信 → 它就是客户端
	if res.IP != "8.8.8.8" {
		t.Fatalf("期望 8.8.8.8（最右的不可信项），实际 %q", res.IP)
	}
}

package realip

import (
	"net/http"
	"testing"
)

func mustResolver(t *testing.T, trusted []string, header string) *Resolver {
	t.Helper()
	r, err := New(Options{TrustedProxies: trusted, Header: header})
	if err != nil {
		t.Fatalf("构造解析器失败：%v", err)
	}
	return r
}

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

// 最要紧的一条：直连对端不可信时，**完全忽略转发头**。
// 否则任何人加一个 X-Forwarded-For 就能伪装成别的 IP（绕过封禁 + 嫁祸他人）。
func TestUntrustedPeerIgnoresForwardedHeaders(t *testing.T) {
	r := mustResolver(t, []string{"10.0.0.0/8"}, "X-Forwarded-For")

	res := r.Resolve("203.0.113.9:5555", hdr("X-Forwarded-For", "1.2.3.4, 5.6.7.8"))
	if res.IP != "203.0.113.9" {
		t.Errorf("对端不可信时必须用对端地址，得到 %q", res.IP)
	}
	if res.Source != "peer" {
		t.Errorf("来源应标为 peer，得到 %q", res.Source)
	}
	if res.PeerTrusted {
		t.Error("203.0.113.9 不该被当成可信代理")
	}
}

// 对端可信时，从右往左找第一个不可信地址。
func TestTrustedPeerWalksChainFromRight(t *testing.T) {
	r := mustResolver(t, []string{"10.0.0.0/8"}, "X-Forwarded-For")

	// 链路：真实客户端 198.51.100.7 → 代理 10.0.0.5 → 代理 10.0.0.6（直连对端）
	res := r.Resolve("10.0.0.6:5555", hdr("X-Forwarded-For", "198.51.100.7, 10.0.0.5"))
	if res.IP != "198.51.100.7" {
		t.Errorf("应当剥掉全部可信代理，得到客户端 198.51.100.7，实际 %q", res.IP)
	}
	if res.Source != "X-Forwarded-For" {
		t.Errorf("来源应标为头名，得到 %q", res.Source)
	}
	if len(res.Chain) != 2 {
		t.Errorf("审计链路应有 2 项，得到 %v", res.Chain)
	}
}

// 紧邻对端的那一项不可信 → 它就是客户端，不该继续往左猜。
func TestNearestHopWinsWhenUntrusted(t *testing.T) {
	r := mustResolver(t, []string{"10.0.0.0/8"}, "X-Forwarded-For")
	// 攻击者伪造最左边的 1.2.3.4，但最右边（真实一跳）是 203.0.113.5
	res := r.Resolve("10.0.0.6:5555", hdr("X-Forwarded-For", "1.2.3.4, 203.0.113.5"))
	if res.IP != "203.0.113.5" {
		t.Errorf("应当取最右侧不可信地址 203.0.113.5，实际 %q（被伪造链骗了）", res.IP)
	}
}

// 链里出现垃圾值：停在已确定的那一跳，不因为一项垃圾丢掉结论。
func TestStopsAtInvalidEntry(t *testing.T) {
	r := mustResolver(t, []string{"10.0.0.0/8"}, "X-Forwarded-For")
	res := r.Resolve("10.0.0.6:5555", hdr("X-Forwarded-For", "not-an-ip, 203.0.113.5"))
	if res.IP != "203.0.113.5" {
		t.Errorf("应当停在有效的 203.0.113.5，实际 %q", res.IP)
	}
}

func TestStripPorts(t *testing.T) {
	r := mustResolver(t, nil, "X-Forwarded-For")
	cases := map[string]string{
		"10.0.0.1:5555":    "10.0.0.1",
		"[2001:db8::1]:80": "2001:db8::1",
		"2001:db8::1":      "2001:db8::1",
		"10.0.0.1":         "10.0.0.1",
	}
	for in, want := range cases {
		if got := stripPort(in); got != want {
			t.Errorf("stripPort(%q) = %q，期望 %q", in, got, want)
		}
		// 顺带确认 Resolve 也处理得对
		if got := r.Resolve(in, nil).IP; got != want {
			t.Errorf("Resolve(%q).IP = %q，期望 %q", in, got, want)
		}
	}
}

// 没配可信代理 = 谁都不信，即使对端看起来像内网。
func TestEmptyTrustedListTrustsNobody(t *testing.T) {
	r := mustResolver(t, nil, "X-Forwarded-For")
	res := r.Resolve("127.0.0.1:1234", hdr("X-Forwarded-For", "8.8.8.8"))
	if res.IP != "127.0.0.1" {
		t.Errorf("没有可信代理时应当用对端地址，实际 %q", res.IP)
	}
}

// 支持单值头（如 X-Real-IP）：对端可信时直接取它。
func TestSingleValueHeader(t *testing.T) {
	r := mustResolver(t, []string{"10.0.0.0/8"}, "X-Real-IP")
	res := r.Resolve("10.0.0.6:5555", hdr("X-Real-IP", "198.51.100.7"))
	if res.IP != "198.51.100.7" {
		t.Errorf("应当取 X-Real-IP，实际 %q", res.IP)
	}
}

// 超长链必须被截断，否则解析本身成了 CPU 放大器。
func TestHopLimit(t *testing.T) {
	r := mustResolver(t, []string{"10.0.0.0/8"}, "X-Forwarded-For")
	long := ""
	for i := 0; i < 500; i++ {
		long += "10.0.0.1, "
	}
	long += "203.0.113.9"
	res := r.Resolve("10.0.0.6:5555", hdr("X-Forwarded-For", long))
	if res.Hops > 32 {
		t.Errorf("检查跳数应被限制在 32 以内，实际 %d", res.Hops)
	}
	if res.IP == "" {
		t.Error("至少要给出一个结论")
	}
}

func TestInvalidTrustedProxyRejected(t *testing.T) {
	if _, err := New(Options{TrustedProxies: []string{"不是IP"}}); err == nil {
		t.Error("非法的 trusted_proxies 条目应当在构造时报错")
	}
}

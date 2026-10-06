package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// 审计发现 F1 的回归测试：webhook 不能打到内网/回环/链路本地地址。
//
// 这条是"控制台可改的字段 → 数据面发起请求"的经典 SSRF 形态，
// 而且原先连重定向都不限制（外部 307 → 内网）。
func TestEgressBlocksPrivateTargets(t *testing.T) {
	pol := egressPolicy{}
	cases := []struct {
		ip     string
		reason string
	}{
		{"127.0.0.1", "回环"},
		{"127.1.2.3", "回环"},
		{"::1", "回环"},
		{"10.0.0.5", "私有"},
		{"172.16.9.9", "私有"},
		{"192.168.1.1", "私有"},
		{"169.254.169.254", "链路本地"}, // 云元数据
		{"0.0.0.0", "未指定"},
		{"100.64.1.1", "NAT"},
		{"224.0.0.1", "组播"},
		{"fd00::1", "私有"},          // IPv6 ULA
		{"::ffff:10.0.0.1", "私有"},  // 4in6 映射（归一化后仍要拦）
		{"::ffff:127.0.0.1", "回环"}, // 4in6 回环
	}
	for _, c := range cases {
		addr := mustAddr(t, c.ip)
		if got := pol.blockedReason(addr); got == "" {
			t.Errorf("%s 应当被拒（%s），实际放行", c.ip, c.reason)
		} else if !strings.Contains(got, c.reason) && c.reason != "NAT" {
			t.Logf("  %s → %s", c.ip, got)
		}
	}

	// 公网地址必须放行，否则告警就发不出去了
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"} {
		if got := pol.blockedReason(mustAddr(t, ip)); got != "" {
			t.Errorf("公网地址 %s 不该被拦，实际：%s", ip, got)
		}
	}
}

// 显式打开 allow_private_hosts 时，内网地址要能放行（自建告警网关的场景）。
func TestEgressAllowPrivateOptIn(t *testing.T) {
	pol := egressPolicy{allowPrivate: true}
	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "169.254.169.254"} {
		if got := pol.blockedReason(mustAddr(t, ip)); got != "" {
			t.Errorf("显式允许私有地址时 %s 不该被拦，实际：%s", ip, got)
		}
	}
}

// 端到端：把 webhook 指向本机回环，投递必须失败且错误信息说明原因。
func TestSendToLoopbackIsBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	}))
	defer srv.Close() // httptest 默认就是 127.0.0.1

	n := New(Options{Enabled: true, Webhook: srv.URL, Timeout: 2 * time.Second})
	defer n.Close()

	err := n.Send(context.Background(), Event{Kind: "test"})
	if err == nil {
		t.Fatal("指向回环的 webhook 必须被出站策略拒绝")
	}
	if !strings.Contains(err.Error(), "出站策略") {
		t.Errorf("错误信息应当点明出站策略，实际：%v", err)
	}
}

// 显式允许时，回环要能真的投递成功（证明拦的是策略、不是把功能打断了）。
func TestSendToLoopbackAllowedWhenOptedIn(t *testing.T) {
	got := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case got <- struct{}{}:
		default:
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()

	n := New(Options{Enabled: true, Webhook: srv.URL, Timeout: 2 * time.Second, AllowPrivateHosts: true})
	defer n.Close()
	if err := n.Send(context.Background(), Event{Kind: "test"}); err != nil {
		t.Fatalf("显式允许私有地址时应当投递成功：%v", err)
	}
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("接收端没有收到告警")
	}
}

// 重定向不跟随：外部地址 307 跳内网这条链必须在第一跳就断掉。
func TestRedirectsAreNotFollowed(t *testing.T) {
	// 目标端（内网回环）——如果客户端跟随重定向，它就会打到这里
	hit := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case hit <- struct{}{}:
		default:
		}
		w.WriteHeader(204)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	// allowPrivate=true 让第一跳能连上（否则会先在出站策略被拒，测不到重定向逻辑）
	n := New(Options{Enabled: true, Webhook: redirector.URL, Timeout: 2 * time.Second, AllowPrivateHosts: true})
	defer n.Close()

	err := n.Send(context.Background(), Event{Kind: "test"})
	if err == nil {
		t.Error("3xx 应当被视为投递失败（不跟随重定向）")
	}
	select {
	case <-hit:
		t.Error("客户端跟随了重定向 —— 这条就是能绕过出站策略的链")
	case <-time.After(300 * time.Millisecond):
	}
}

// ValidateWebhook 用于控制台保存前校验。
func TestValidateWebhook(t *testing.T) {
	bad := []string{
		"ftp://example.com/hook",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"example.com/hook", // 无 scheme
		"http://127.0.0.1:8080/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.1.2.3/hook",
		"http://",
	}
	for _, u := range bad {
		if err := ValidateWebhook(u, false); err == nil {
			t.Errorf("%q 应当被拒绝", u)
		}
	}
	good := []string{
		"https://hooks.example.com/services/xxx",
		"http://203.0.113.10/hook", // TEST-NET-3，公网可路由
	}
	for _, u := range good {
		if err := ValidateWebhook(u, false); err != nil {
			t.Errorf("%q 应当被接受，实际：%v", u, err)
		}
	}
	// 显式允许私有地址后，内网地址可用
	if err := ValidateWebhook("http://10.1.2.3/hook", true); err != nil {
		t.Errorf("显式允许私有地址时应当接受：%v", err)
	}
}

// mustAddr 解析 IP 字面量，失败即让测试失败。
func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("测试用例里的 IP 写错了：%q", s)
	}
	return a
}

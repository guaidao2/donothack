package notify

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// 本文件是告警通道的**出站策略**（审计发现 F1）。
//
// 问题：`/notify` 只校验了 `http(s)://` 前缀，然后由数据面发起请求。
// 这等于给了"改 webhook 的人"一个从 WAF 机器发起内网请求的能力 ——
// 可以打 `http://127.0.0.1:<控制台端口>/`、内网服务、云元数据 `169.254.169.254`；
// 而且 http.Client 默认跟随 10 跳重定向，先给一个外部地址再 307 跳到内网同样成立。
// 更糟的是 `/notify/test` 会把对端状态码回显出来，构成一个稳定的内网端口探测器。
//
// 三条防线（缺一不可）：
//  1. **不发私有地址**：解析出的 IP 落在回环/私有/链路本地/CGNAT/未指定等范围就拒绝；
//  2. **在连接时校验**：只查一次配置期的域名会被 DNS 重绑定绕过 ——
//     所以校验放在 DialContext 里，校验的就是**即将连的那个 IP**；
//  3. **不跟随重定向**：3xx 一律视为投递失败并如实报告，
//     否则"外部地址 307 → 内网"这条绕过依然成立。
//
// 需要打内网 webhook（自建告警网关）时，显式开 `alert.allow_private_hosts: true`。

// egressPolicy 描述出站限制。
type egressPolicy struct {
	allowPrivate bool
}

// blockedReason 返回"该 IP 为什么被拒"，空串表示放行。
//
// 刻意做成**白名单式**：默认拒绝一切非公网可路由地址，
// 而不是列举几个已知的内网段 —— 后者总会漏（新保留段、IPv6 特例、4in6 映射…）。
func (e egressPolicy) blockedReason(addr netip.Addr) string {
	if e.allowPrivate {
		return ""
	}
	// 4in6 映射地址（::ffff:127.0.0.1）先归一化，否则会绕过判断。
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	switch {
	case !addr.IsValid():
		return "地址无效"
	case addr.IsUnspecified():
		return "未指定地址（0.0.0.0 / ::）"
	case addr.IsLoopback():
		return "回环地址"
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return "链路本地地址（含云元数据 169.254.169.254）"
	case addr.IsInterfaceLocalMulticast(), addr.IsMulticast():
		return "组播地址"
	case addr.IsPrivate():
		return "私有地址"
	case addr.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(addr):
		return "运营级 NAT 地址（100.64.0.0/10）"
	case addr.Is4() && netip.MustParsePrefix("192.0.0.0/24").Contains(addr):
		return "IETF 协议专用地址（192.0.0.0/24）"
	case addr.Is4() && netip.MustParsePrefix("198.18.0.0/15").Contains(addr):
		return "基准测试地址（198.18.0.0/15）"
	}
	return ""
}

// newHTTPClient 构造带出站策略的客户端。
func newHTTPClient(timeout time.Duration, pol egressPolicy) *http.Client {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, fmt.Errorf("目标地址无法解析：%w", err)
				}
				// 先解析成 IP，**校验的就是将要连接的那个 IP**（防 DNS 重绑定）。
				ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
				if err != nil {
					return nil, fmt.Errorf("解析 webhook 域名 %s 失败：%w", host, err)
				}
				var lastErr error
				for _, ip := range ips {
					if reason := pol.blockedReason(ip); reason != "" {
						lastErr = fmt.Errorf("webhook 目标 %s 解析到 %s（%s），按出站策略拒绝%s",
							host, ip, reason, allowPrivateHint)
						continue
					}
					conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
					if err == nil {
						return conn, nil
					}
					lastErr = err
				}
				if lastErr == nil {
					lastErr = fmt.Errorf("webhook 域名 %s 没有可用地址", host)
				}
				return nil, lastErr
			},
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		},
		// 不跟随重定向：跟随会让"外部地址 307 → 内网"绕过上面的校验。
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("webhook 返回重定向（%d 跳，目标 %s）；出于出站安全策略不跟随，请直接把 webhook 配成最终地址",
				len(via), req.URL.Host)
		},
	}
}

const allowPrivateHint = "；若确实需要打内网地址，请显式配置 alert.allow_private_hosts: true"

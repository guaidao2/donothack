// Package realip 从请求中解析"真实客户端 IP"。
//
// 这看起来是个小函数，但它是**限速与封禁的地基**：取错了 IP，
// 要么所有人都被算成同一个 IP（一个攻击者就能把全站限死），
// 要么攻击者随便伪造 XFF 就绕过了封禁。两种后果都比"没有限速"更糟。
//
// 判据：
//  1. 先看**直连对端**（RemoteAddr）。它不在 trusted_proxies 里 →
//     一律用对端地址，**忽略全部转发头**。伪造 XFF 到此为止。
//  2. 对端可信时，从链的**最右**往左走：最右是最近一跳看到的地址。
//     只要当前地址仍是可信代理就继续往左，遇到的第一个不可信地址就是客户端。
//  3. 链里出现非法值（域名、"unknown"、空串）→ 停止，用已确定的那一跳。
//  4. 最多看 maxHops 个（默认 32）：防止有人塞几万项 XFF 让解析变成 CPU 放大器。
package realip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// Options 是解析器构造参数。
type Options struct {
	// TrustedProxies 是可信代理的 CIDR 列表。**空列表 = 不信任任何转发头**。
	TrustedProxies []string
	// Header 是承载链路或单值的头名（默认 X-Forwarded-For）。
	Header string
	// MaxHops 是单次解析最多检查的链长度。
	MaxHops int
}

// Resolver 是编译好的解析器。构建后只读，可并发使用。
type Resolver struct {
	trusted []netip.Prefix
	header  string
	maxHops int
}

// New 编译解析器。
func New(o Options) (*Resolver, error) {
	r := &Resolver{
		header:  http.CanonicalHeaderKey(strings.TrimSpace(o.Header)),
		maxHops: o.MaxHops,
	}
	if r.header == "" {
		r.header = "X-Forwarded-For"
	}
	if r.maxHops <= 0 {
		r.maxHops = 32
	}
	for _, s := range o.TrustedProxies {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(s); err == nil {
			r.trusted = append(r.trusted, pfx.Masked())
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			r.trusted = append(r.trusted, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		return nil, fmt.Errorf("trusted_proxies 里的 %q 既不是 CIDR 也不是 IP", s)
	}
	return r, nil
}

// TrustedCount 返回可信代理条目数（启动日志用）。
func (r *Resolver) TrustedCount() int { return len(r.trusted) }

// Result 是解析结果。
type Result struct {
	// IP 是最终认定的客户端地址（字符串形式）。
	IP string
	// Peer 是直连对端的地址。
	Peer string
	// PeerTrusted 表示直连对端是否在可信代理列表里。
	PeerTrusted bool
	// Source 说明这个 IP 是怎么来的："peer"（对端）或头名。
	Source string
	// Hops 是实际检查过的链条长度。
	Hops int
	// Chain 是解析出的代理链（最左为最初客户端），仅用于审计，最多留 8 项。
	Chain []string
}

// IsTrusted 判断地址是否落在可信代理范围内。
func (r *Resolver) IsTrusted(addr netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Resolve 解析客户端 IP。
func (r *Resolver) Resolve(remoteAddr string, h http.Header) Result {
	peer := stripPort(remoteAddr)
	res := Result{Peer: peer, IP: peer, Source: "peer"}

	peerAddr, err := netip.ParseAddr(peer)
	if err != nil {
		// 对端地址都解析不出来（理论上不该发生）→ 原样返回，绝不猜。
		return res
	}
	res.PeerTrusted = r.IsTrusted(peerAddr)
	if !res.PeerTrusted {
		// 对端不可信：**完全忽略转发头**。这是防伪造的关键一步。
		return res
	}

	raw := h.Get(r.header)
	if raw == "" {
		return res
	}

	parts := strings.Split(raw, ",")

	// **截断必须保留最右边的 maxHops 项。**
	//
	// 下面是从右往左看的（最右 = 最近一跳），所以丢掉的应该是**最左边**那些
	// 攻击者可随意伪造的历史项。原先写成 `parts[:maxHops]` 是反的：
	// 攻击者在 XFF 里塞满 32 项，负载均衡器追加的真实 IP 正好被截掉，
	// 于是判定从攻击者写的那一项开始 —— 不在 trusted_proxies 里就直接当成客户端 IP,
	// 每个请求都能自称任意 IP：限速（新 key 直接拿满桶）、封禁累计、审计里的
	// client_ip 全部失效，限速表还会被冲爆。
	if len(parts) > r.maxHops {
		parts = parts[len(parts)-r.maxHops:]
	}

	// 从右往左：最右是最近一跳看到的地址。
	// 逐项剥离可信代理，遇到第一个不可信的地址就是客户端。
	chain := make([]string, 0, len(parts))
	for i := len(parts) - 1; i >= 0; i-- {
		res.Hops++
		item := strings.TrimSpace(parts[i])
		// 去掉可能存在的端口（有些代理会写 ip:port）
		item = stripPort(item)
		addr, err := netip.ParseAddr(item)
		if err != nil {
			// 非法值：停止，保留当前结论（不因为一项垃圾就丢掉已确定的结果）
			break
		}
		if i == len(parts)-1 {
			res.IP = addr.String()
			res.Source = r.header
		}
		chain = append(chain, addr.String())
		if !r.IsTrusted(addr) {
			res.IP = addr.String()
			res.Source = r.header
			break
		}
		// 这一跳也是可信代理，继续往左找
		res.IP = addr.String()
		res.Source = r.header
	}

	// 审计用的链路：反转为"最左=最初客户端"，最多 8 项
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	if len(chain) > 8 {
		chain = chain[:8]
	}
	res.Chain = chain
	return res
}

// stripPort 去掉 "1.2.3.4:5678" 或 "[::1]:80" 里的端口。
func stripPort(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	// [::1]:80 形式
	if strings.HasPrefix(host, "[") {
		if i := strings.Index(host, "]"); i >= 0 {
			return host[1:i]
		}
		return strings.Trim(host, "[]")
	}
	// 只有一个冒号才可能是 IPv4:port；IPv6 裸地址有多个冒号，不动它
	if strings.Count(host, ":") == 1 {
		if i := strings.LastIndex(host, ":"); i > 0 {
			if _, err := strconv.Atoi(host[i+1:]); err == nil {
				return host[:i]
			}
		}
	}
	return host
}

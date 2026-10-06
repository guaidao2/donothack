package server

import (
	"net"
	"sync/atomic"
)

// limitListener 给监听器加上**并发连接数**上限。
//
// 为什么必须在连接层再限一次：
// `MaxConns` 原先只作用于 http.Handler（信号量包在 mux 外面），
// 也就是"同时处理的请求数"。而**连接本身**没有上限 —— 攻击者开两万个只连不发、
// 或者发一半 header 的连接，每个连接仍占着 net/http 的读缓冲与 goroutine；
// 512 MiB 档上每连接十几到几十 KB，一两万条就能把内存吃穿。
// 而 `ReadHeaderTimeout` 只能让单个慢连接最终被清掉，挡不住"同时灌满"。
//
// 语义：Accept 在超过上限时**阻塞**（内核 backlog 顶住），
// 而不是直接拒绝 —— 拒绝会让正常流量在瞬时的连接高峰里看到失败。
// 这样上限是硬的，代价只是排队。
type limitListener struct {
	net.Listener
	sem chan struct{}

	// 当前连接数（含已 Accept 未 Close 的），供 /readyz 观测。
	current atomic.Int64
	// 因为超限被迫排队等待的次数，供 /readyz 观测。
	waited atomic.Int64
}

func newLimitListener(ln net.Listener, max int) net.Listener {
	if max <= 0 {
		return ln
	}
	return &limitListener{Listener: ln, sem: make(chan struct{}, max)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	default:
		l.waited.Add(1)
		l.sem <- struct{}{} // 满则阻塞，等一个名额
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	l.current.Add(1)
	return &limitConn{Conn: c, release: func() {
		l.current.Add(-1)
		<-l.sem
	}}, nil
}

func (l *limitListener) Stats() (current, waited int64) {
	return l.current.Load(), l.waited.Load()
}

// limitConn 在关闭时释放名额（只释放一次）。
type limitConn struct {
	net.Conn
	release func()
	closed  atomic.Bool
}

func (c *limitConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.release()
	}
	return c.Conn.Close()
}

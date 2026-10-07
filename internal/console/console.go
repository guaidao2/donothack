// Package console 是运维控制台：独立的监听端口、独立的 mux、独立的一套防护。
//
// 与数据面的关系：
//
//   - **完全分离**：控制台流量**不进检测引擎** —— 否则管理员改规则时可能被自己的规则拦掉。
//   - **只读数据面状态**：控制台通过 control 包读写配置，数据面通过原子快照读取。
//     控制台卡住、被攻击、甚至挂掉，都不影响转发与检测。
//   - **重活不许做**：只查内存 ring buffer 与最近几分钟的聚合桶，
//     禁止扫全量历史（2C2G 上先翻车的就是这里）。
package console

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"donothack/internal/audit"
	"donothack/internal/config"
	"donothack/internal/control"
	"donothack/internal/eventstore"
	"donothack/internal/notify"
	"donothack/internal/ratelimit"
	"donothack/internal/realip"

	"donothack"
)

// Options 是控制台构造参数。
type Options struct {
	Config   *config.Config
	Control  *control.Control
	Events   *eventstore.Store
	Limiter  *ratelimit.Limiter
	Resolver *realip.Resolver
	Logger   *audit.Logger
	Version  string

	// Notifier 是告警通道（GET/PUT /notify 会读改它）。
	Notifier *notify.Notifier
	// ApplyNotifier 把新的发送器推给数据面（改完 webhook 要立刻生效）。
	ApplyNotifier func(*notify.Notifier)

	// EventSummary 提供数据面侧的统计（拦截数、限速数、降级档位）。
	EventSummary func() map[string]any
	// ReadyInfo 提供 /readyz 风格的就绪信息。
	ReadyInfo func() map[string]any
}

// Server 是控制台服务。
type Server struct {
	o Options

	mux         *http.ServeMux
	login       *hashState
	totp        *hashState // **生效的** TOTP 密钥（与 login 同构：读写加锁）
	totpPending *hashState // 待确认的密钥：生成它不影响生效状态
	totpOn      atomic.Bool
	assets      fs.FS
	session     *sessionStore
	secret      []byte // CSRF 签名密钥

	// 登录爆破防护：按 admin.max_login_fails / admin.lockout 生效
	// （原先这几个配置项零引用，实际阈值来自数据面的 ratelimit，
	// 而 ratelimit 一关就完全没有次数控制）。
	loginThrottle *loginThrottle

	csrfFails   atomic.Uint64
	loginFails  atomic.Uint64
	blockedReqs atomic.Uint64
	logins      atomic.Uint64
}

// New 构造控制台。**会在 password_hash 为空时生成随机初始密码并返回它**，
// 由调用方打印一次（绝不使用默认密码）。
func New(o Options) (*Server, string, error) {
	if o.Config == nil {
		return nil, "", fmt.Errorf("缺少配置")
	}
	assets, err := fs.Sub(donothack.WebFS, "web")
	if err != nil {
		return nil, "", fmt.Errorf("前端资源嵌入失败：%w", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", err
	}

	s := &Server{
		o:       o,
		assets:  assets,
		session: newSessionStore(256),
		secret:  secret,

		// 登录爆破：按 admin.max_login_fails / admin.lockout 生效。
		// 阈值留空时给保守默认（5 次 / 5 分钟窗口 / 15 分钟封禁）。
		loginThrottle: newLoginThrottle(o.Config.Admin.MaxLoginFails,
			o.Config.Admin.Lockout.D(), o.Config.Admin.Lockout.D()),
	}

	// 初始密码：配置里没有 password_hash 时生成一个随机密码并返回。
	// **绝不使用 admin/admin 之类的默认口令。**
	initial := ""
	loginHash := o.Config.Admin.PasswordHash
	if strings.TrimSpace(loginHash) == "" {
		pw, err := generatePassword()
		if err != nil {
			return nil, "", err
		}
		hash, err := hashPassword(pw)
		if err != nil {
			return nil, "", err
		}
		loginHash = hash
		initial = pw
	}
	s.login = &hashState{passwordHash: loginHash}

	// TOTP：配置里带密钥且开关打开才算启用。
	// 只开开关不给密钥是**有意**判定为"未启用"的 —— 否则每个实例重启后
	// 都拿着一把自己生成的密钥，而运维的认证器里那把就成了废码。
	s.totp = &hashState{passwordHash: o.Config.Admin.TOTPSecret}
	// 待确认密钥与生效密钥**分开存**：生成一把新密钥（enroll）不应该动生效状态，
	// 否则"会话里点一次绑定"就等于把两步验证关掉了。
	s.totpPending = &hashState{}
	if o.Config.Admin.TOTPEnabled && strings.TrimSpace(o.Config.Admin.TOTPSecret) != "" {
		s.totpOn.Store(true)
	}

	s.routes()
	return s, initial, nil
}

// Addr 返回控制台的监听地址。
func (s *Server) Addr() string { return s.o.Config.Admin.Addr }

// AllowInsecure 报告运维是否显式允许明文绑定非本机地址。
//
// Basic 门槛凭据是 base64 不是加密，明文暴露等于把门槛凭据送给链路上的任何人。
// 所以明文绑定非本机地址必须显式确认，而不是"忘了配 TLS 就默认放行"。
func (s *Server) AllowInsecure() bool { return s.o.Config.Admin.AllowInsecure }

// URL 返回控制台的访问地址。
func (s *Server) URL() string {
	scheme := "http"
	if s.tlsEnabled() {
		scheme = "https"
	}
	return scheme + "://" + s.o.Config.Admin.Addr + "/"
}

// ---------------------------------------------------------------- 路由

// apiRoutePaths 记录注册过的 /api/v1/* 路径，只服务"所有 API 默认必须认证"的回归测试：
// 以后新增路由会自动进入覆盖范围，不必手工维护清单（清单总会漏）。
var apiRoutePaths []string

func (s *Server) routes() {
	mux := http.NewServeMux()
	apiRoutePaths = apiRoutePaths[:0]
	h := func(p string, fn http.HandlerFunc) {
		if strings.HasPrefix(p, "/api/v1/") {
			apiRoutePaths = append(apiRoutePaths, p)
		}
		mux.HandleFunc(p, fn)
	}

	// 认证
	h("/api/v1/login", s.handleLogin)
	h("/api/v1/logout", s.handleLogout)
	h("/api/v1/session", s.handleSession)
	h("/api/v1/password", s.handlePassword)

	// 状态与统计
	h("/api/v1/status", s.handleStatus)
	h("/api/v1/metrics/summary", s.handleMetricsSummary)
	h("/api/v1/metrics/timeseries", s.handleTimeseries)

	// 事件
	h("/api/v1/events", s.handleEvents)
	h("/api/v1/events/", s.handleEventByID) // /events/:id 与 /events/:id/raw
	h("/api/v1/events/stream", s.handleEventsStream)
	h("/api/v1/events/export", s.handleEventsExport)

	// 规则
	h("/api/v1/rules", s.handleRules)
	h("/api/v1/rules/", s.handleRuleByID)
	h("/api/v1/rules/validate", s.handleRulesValidate)
	h("/api/v1/rules/test", s.handleRulesTest)
	h("/api/v1/rulesets/reload", s.handleRulesReload)
	h("/api/v1/rules/sync", s.handleRulesSync)
	h("/api/v1/rulesets/preview", s.handleRulesPreview)
	h("/api/v1/rulesets", s.handleRuleSets)

	// 拦截页（本次新增：内容可在控制台里改）
	h("/api/v1/block-page", s.handleBlockPage)
	h("/api/v1/block-page/preview", s.handleBlockPagePreview)

	// 限速与封禁
	h("/api/v1/ratelimit", s.handleRateLimit)
	h("/api/v1/bans", s.handleBans)
	h("/api/v1/bans/", s.handleBanByIP)

	// 例外与 IP 名单
	h("/api/v1/exceptions", s.handleExceptions)
	h("/api/v1/exceptions/", s.handleExceptions)
	h("/api/v1/ip-lists", s.handleIPLists)
	h("/api/v1/ip-lists/", s.handleIPLists)

	// 备份恢复
	h("/api/v1/backup", s.handleBackup)
	h("/api/v1/restore", s.handleRestore)

	// 配置与审计
	h("/api/v1/totp/enroll", s.handleTOTPEnroll)
	h("/api/v1/totp/disable", s.handleTOTPDisable)

	h("/api/v1/notify", s.handleNotify)
	h("/api/v1/notify/test", s.handleNotifyTest)

	h("/api/v1/config", s.handleConfig)
	h("/api/v1/config/diff", s.handleConfigDiff)
	h("/api/v1/config/reload", s.handleConfigReload)
	// 引擎热参数（模式 / 阈值 / 命中即封禁）：整份 PUT /config 是被有意拒绝的，
	// 但"应急切模式"必须有页面入口 —— 走这个专用端点，底层同一条 control.Apply。
	h("/api/v1/engine", s.handleEngine)
	h("/api/v1/console-audit", s.handleConsoleAudit)

	// 静态资源与 SPA 兜底
	mux.HandleFunc("/", s.handleStatic)

	s.mux = mux
}

// apiAuthAllowlist 是唯一允许匿名访问的 API 端点：登录本身。
//
// 别的东西一律要走会话 —— 白名单是**显式声明**的，新增路由默认受保护。
var apiAuthAllowlist = map[string]bool{
	"/api/v1/login": true,
}

// requireSessionForAPI 给所有 /api/v1/* 统一兜一层会话校验。
//
// 为什么要有这一层：`GET /api/v1/engine` 曾经漏挂 requireRead，匿名就能读到
// 引擎参数（mode / 阈值 / 封禁时长）—— 同一批端点里只有它漏，因为校验是
// **逐个 handler 手工挂**的，漏一个就是一个洞，而且不会自己暴露。
// 兜上这层之后，漏挂只会得到 401，不会再对外泄数据；方法检查也拦不住它
// （以前 POST-only 端点未认证时先回 405，现在先回 401）。
func (s *Server) requireSessionForAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/v1/") {
			trimmed := strings.TrimSuffix(p, "/")
			if !apiAuthAllowlist[p] && !apiAuthAllowlist[trimmed] {
				if _, ok := s.currentSession(r); !ok {
					s.writeError(w, http.StatusUnauthorized, "unauthenticated", "需要先登录", "")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Handler 返回带完整防护链的处理器。
func (s *Server) Handler() http.Handler {
	// 认证兜底放在准入之后、mux 之前：所有 /api/v1/* 统一要求会话
	// （唯一白名单是登录本身，见 apiAuthAllowlist）。
	// 逐个 handler 手工挂校验的写法漏过一个（GET /engine），所以改成兜底。
	return s.admissionMiddleware(s.requireSessionForAPI(s.mux))
}

// admissionMiddleware 是控制台唯一的准入层：**来源地址白名单**。
//
// 认证不在这里：真正的边界是表单登录 + 会话（`/api/v1/login` 与 `requireWrite`）。
// 曾经这里还有一层 HTTP Basic「门槛」，用来不让扫描器看见门 —— 已移除：
// 它只提供"遮挡"不提供安全，却让运维多记一套凭据、还要面对浏览器反复弹窗，
// 收益远小于代价。
func (s *Server) admissionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		if !s.ipAllowed(ip) {
			s.deny(w, "来源地址不在允许列表内")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// deny 统一输出 403。
//
// **不带 Server 头、不带产品特征**；响应体极简。
func (s *Server) deny(w http.ResponseWriter, _ string) {
	h := w.Header()
	h.Del("Server")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("403 Forbidden\n"))
}

func (s *Server) clientIP(r *http.Request) string {
	if s.o.Resolver != nil {
		return s.o.Resolver.Resolve(r.RemoteAddr, r.Header).IP
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		return host[:i]
	}
	return host
}

func (s *Server) ipAllowed(ip string) bool {
	list := s.o.Config.Admin.AllowIPs
	if len(list) == 0 {
		return true
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, item := range list {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(item); err == nil {
			if cidr.Contains(addr) {
				return true
			}
			continue
		}
		if net.ParseIP(item) != nil && net.ParseIP(item).Equal(addr) {
			return true
		}
	}
	return false
}

func (s *Server) tokenValid(r *http.Request) bool {
	want := strings.TrimSpace(s.o.Config.Admin.APIToken)
	if want == "" {
		return false
	}
	got := r.Header.Get(tokenHeader)
	if got == "" {
		if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
			got = strings.TrimPrefix(a, "Bearer ")
		}
	}
	if got == "" {
		return false
	}
	// 常数时间比较
	if len(got) != len(want) {
		return false
	}
	var diff byte
	for i := 0; i < len(got); i++ {
		diff |= got[i] ^ want[i]
	}
	return diff == 0
}

// ---------------------------------------------------------------- 静态资源

// handleStatic 提供前端资源。
//
// 三件事必须做对：
//  1. **SPA 兜底**：深链接（/events/xxx）没有对应文件时回落到 index.html，
//     否则用户刷新页面就 404。
//  2. **`<base href>` 改写**：控制台可能挂在 /c/<token>/ 前缀下，
//     不改写的话深链接里的 assets 相对路径会算错（实测踩过）。
//  3. **缓存**：用 ETag 让浏览器每次花一次 304 的代价确认，
//     避免升级后拿着旧 JS 跑（无构建链，没法用文件名哈希做缓存失效）。
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if isWriteMethod(r.Method) {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "静态资源不支持写操作", "")
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		p = "index.html"
	}

	// index.html 永远走改写路径
	if p == "index.html" || !strings.Contains(p, ".") {
		s.serveIndex(w, r)
		return
	}

	f, err := s.assets.Open(p)
	if err != nil {
		// 有扩展名但找不到：走 SPA 兜底（前端可能用带点的路由）
		s.serveIndex(w, r)
		return
	}
	defer func() { _ = f.Close() }()

	stat, err := f.Stat()
	if err != nil || stat.IsDir() {
		s.serveIndex(w, r)
		return
	}
	// 先算 ETag（内容哈希），再决定要不要回 304
	data, err := readAll(f, stat.Size())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "read_failed", "读取静态资源失败", err.Error())
		return
	}
	etag := `"` + shortHash(data) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", contentTypeOf(p))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// serveIndex 输出改写后的 index.html。
func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(s.assets, "index.html")
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "index_missing", "前端外壳缺失", err.Error())
		return
	}
	// 控制台固定挂在根路径：index.html 里的 <base href="/"> 与 <meta name="dh-base">
	// 本来就是对的，不需要在响应里改写。
	//
	// 以前这里会按挂载前缀改写它们，而 CSP 的 `base-uri 'none'` 会把改写结果拦下来
	// （浏览器控制台每加载一次就报一条）—— 既然前缀已固定，干脆不改。
	body := []byte(data)
	etag := `"` + shortHash(body) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// 控制台页面同样要有基本的安全头。
	//
	// Referrer-Policy 统一为 no-referrer（-03：文档写 no-referrer、
	// 代码写 same-origin，而 index.html 的 meta 又是第三种说法）。
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	// **CSP**。
	//
	// 取值刻意解释一遍，避免以后有人"照着最常见的模板"改坏：
	//   - script-src 'self'：前端是原生 ES module、没有内联脚本，可以用最严的；
	//   - style-src 'self' 'unsafe-inline'：有少量元素级 style，禁掉会破坏布局；
	//     样式注入的危害远小于脚本注入，这个折中是有意的；
	//   - connect-src 'self'：只与自身 API 通信（含 SSE）；
	//   - base-uri 'self'：前端用 `<base href="/">` 决定"相对资源与路由相对谁"，
	//     深层链接（直接打开 /events/42）就靠它。**不能用 'none'** ——
	//     那会把 index.html 里的 <base> 一起拦掉（浏览器每次加载报一条 CSP 错），
	//     深层链接下的 assets 会解析到 /events/assets/* 而白屏。
	//     'self' 既放行同源 base，又挡住"注入一个外部 base 改写所有相对 URL"。
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self'; font-src 'self'; "+
			"object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
	_, _ = w.Write(body)
}

// rewriteMetaBase 已随"固定根路径"一起移除：前端读的 <meta name="dh-base"> 就是 "/"，
// 不需要在响应里改写（改写还会被 CSP 的 base-uri 'none' 拦下并报错）。

// ---------------------------------------------------------------- TLS

func (s *Server) tlsEnabled() bool {
	return s.o.Config.Admin.TLS.Enabled
}

// TLSConfig 生成本控制台监听用的 TLS 配置。
//
// 未配证书时自动生成自签证书（标准库 crypto/x509，SAN 含主机名与本机 IP）。
// **证书只放在内存里**：把私钥写到磁盘上会多出一份需要保护的文件，
// 而自签证书本来就要点一次"继续访问"，持久化并没有实际收益。
func (s *Server) TLSConfig() (*tls.Config, error) {
	cfg := s.o.Config.Admin.TLS
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("加载控制台证书失败：%w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}

	host := s.o.Config.Admin.Addr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	certPEM, keyPEM, err := selfSignedCert(host)
	if err != nil {
		return nil, fmt.Errorf("生成自签证书失败：%w", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if s.o.Logger != nil {
		s.o.Logger.App().Warn("控制台使用自动生成的自签证书",
			"addr", s.o.Config.Admin.Addr,
			"hint", "浏览器会提示证书不受信任；正式部署建议配置自己的证书（admin.tls.cert_file/key_file）")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// selfSignedCert 生成自签证书（1 年有效，SAN 含主机名与本机 IP）。
func selfSignedCert(host string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "donothack-console"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		if ip := net.ParseIP(host); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, host)
		}
	}
	tmpl.DNSNames = append(tmpl.DNSNames, "localhost")
	tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	if ip := localIP(); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// localIP 找一个非回环的本机 IPv4 地址放进 SAN，方便用内网地址访问。
func localIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if v4 := ipnet.IP.To4(); v4 != nil {
				return v4
			}
		}
	}
	return nil
}

// totpEnabled 报告 TOTP 是否真正生效（开关打开 **且** 有密钥）。
func (s *Server) totpEnabled() bool {
	return s.totpOn.Load() && strings.TrimSpace(s.totp.get()) != ""
}

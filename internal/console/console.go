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
	"strconv"
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
	gate        *gateState
	login       *gateState
	totp        *gateState // **生效的** TOTP 密钥（与 gateState 同构：读写加锁）
	totpPending *gateState // 待确认的密钥：生成它不影响生效状态
	totpOn      atomic.Bool
	assets      fs.FS
	mount       string // 挂载前缀（gate.path_token 生效时非空）
	session     *sessionStore
	secret      []byte // CSRF 签名密钥

	// 按配置生效的两道封禁（-02：原先 admin.max_login_fails /
	// admin.lockout / gate.probe_ban_* 全是零引用，实际阈值来自数据面的
	// ratelimit.ban_after_hits，而且 ratelimit 一关就完全失去次数控制）。
	loginThrottle *loginThrottle
	probeThrottle *loginThrottle

	csrfFails   atomic.Uint64
	gateFails   atomic.Uint64
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

	mount := ""
	if o.Config.Admin.Gate.Enabled && o.Config.Admin.Gate.PathToken != "" {
		// **与轮换接口走同一套字符收敛**。
		// mount 会被拼进 SPA 的 `<base href>`，直接信任配置值等于允许属性注入；
		// 而 `..`、`?` 这类取值还会让 mux 注册期 panic（进程直接起不来）。
		token := sanitizePathToken(o.Config.Admin.Gate.PathToken)
		if token == "" {
			return nil, "", fmt.Errorf("admin.gate.path_token 过滤后为空：只允许字母、数字、- 和 _")
		}
		mount = "/c/" + token
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", err
	}

	s := &Server{
		o:       o,
		assets:  assets,
		mount:   mount,
		session: newSessionStore(256),
		secret:  secret,

		// 登录爆破：按 admin.max_login_fails / admin.lockout 生效。
		// 阈值留空时给保守默认（5 次 / 5 分钟窗口 / 15 分钟封禁）。
		loginThrottle: newLoginThrottle(o.Config.Admin.MaxLoginFails,
			o.Config.Admin.Lockout.D(), o.Config.Admin.Lockout.D()),
		// 门槛（Basic）探测：按 gate.probe_ban_after / probe_ban_window / probe_ban_duration 生效。
		probeThrottle: newLoginThrottle(o.Config.Admin.Gate.ProbeBanAfter,
			o.Config.Admin.Gate.ProbeBanWindow.D(), o.Config.Admin.Gate.ProbeBanDuration.D()),
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
	s.login = &gateState{passwordHash: loginHash}

	// TOTP：配置里带密钥且开关打开才算启用。
	// 只开开关不给密钥是**有意**判定为"未启用"的 —— 否则每个实例重启后
	// 都拿着一把自己生成的密钥，而运维的认证器里那把就成了废码。
	s.totp = &gateState{passwordHash: o.Config.Admin.TOTPSecret}
	// 待确认密钥与生效密钥**分开存**：生成一把新密钥（enroll）不应该动生效状态，
	// 否则"会话里点一次绑定"就等于把两步验证关掉了。
	s.totpPending = &gateState{}
	if o.Config.Admin.TOTPEnabled && strings.TrimSpace(o.Config.Admin.TOTPSecret) != "" {
		s.totpOn.Store(true)
	}

	// 门槛凭据是**另一套**（可以单独轮换、可以交给运维同事）。
	// 首次运行时若没配门槛凭据，就用同一个初始密码再哈希一次 ——
	// 让运维只抄一个口令进门；之后可以各自轮换。
	//
	// 注意：**只有门槛真的启用时才需要它**。门槛关掉（gate.enabled: false
	// 或 mode: none）却还强制要求门槛口令，会让"只想跑一个不带门槛的本地控制台"
	// 直接起不来 —— 这是个实际踩到的启动失败。
	gateHash := o.Config.Admin.Gate.PasswordHash
	if gateNeeded(o.Config) {
		if strings.TrimSpace(gateHash) == "" {
			if initial == "" {
				return nil, "", fmt.Errorf("启用门槛时必须配置 admin.gate.password_hash" +
					"（或留空 admin.password_hash 让程序生成初始口令）")
			}
			h, err := hashPassword(initial)
			if err != nil {
				return nil, "", err
			}
			gateHash = h
		}
	}
	s.gate = &gateState{passwordHash: gateHash}

	s.routes()
	return s, initial, nil
}

// gateNeeded 判断门槛是否真的启用。
//
// enabled 与 mode 都要看：mode=none 表示明确不要门槛（即便 enabled 为真）。
func gateNeeded(cfg *config.Config) bool {
	if !cfg.Admin.Gate.Enabled {
		return false
	}
	return cfg.Admin.Gate.Mode != "none"
}

// Mount 返回控制台的挂载前缀。
func (s *Server) Mount() string { return s.mount }

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
	return scheme + "://" + s.o.Config.Admin.Addr + s.mount + "/"
}

// ---------------------------------------------------------------- 路由

func (s *Server) routes() {
	mux := http.NewServeMux()
	h := func(p string, fn http.HandlerFunc) {
		mux.HandleFunc(s.mount+p, fn)
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
	h("/api/v1/rulesets/preview", s.handleRulesPreview)
	h("/api/v1/rulesets", s.handleRuleSets)

	// 拦截页（本次新增：内容可在控制台里改）
	h("/api/v1/block-page", s.handleBlockPage)
	h("/api/v1/block-page/preview", s.handleBlockPagePreview)

	// 限速与封禁
	h("/api/v1/ratelimit", s.handleRateLimit)
	h("/api/v1/bans", s.handleBans)
	h("/api/v1/bans/", s.handleBanByIP)

	// 门槛
	h("/api/v1/gate", s.handleGate)
	h("/api/v1/gate/rotate", s.handleGateRotate)
	h("/api/v1/gate/cert/selfsigned", s.handleGateCertSelfSigned)
	h("/api/v1/gate/path/rotate", s.handleGatePathRotate)

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
	h("/api/v1/console-audit", s.handleConsoleAudit)

	// 静态资源与 SPA 兜底
	mux.HandleFunc(s.mount+"/", s.handleStatic)

	s.mux = mux
}

// Handler 返回带完整防护链的处理器。
func (s *Server) Handler() http.Handler {
	return s.gateMiddleware(s.mux)
}

// gateMiddleware 是第一层准入。
//
// 铁律：**未过门槛时，所有路径统一返回 401**，不区分路径是否存在。
// 用 404 区分"路径不存在"会立刻暴露这是一个有内容的服务，
// 扫描器据此就能把控制台从一堆端口里挑出来。
func (s *Server) gateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)

		// API token 可跳过门槛（CLI 用），但**仍然需要会话或 token 才能调 API**。
		//
		// 这里同时受 `admin.gate.exempt_api_token` 控制：
		// 原先只要 token 对就一路免掉 IP 白名单、限速、探测封禁，
		// 而那个配置项根本没人读 —— 运维以为关掉了，其实关不掉。
		hasToken := s.tokenValid(r) && s.o.Config.Admin.Gate.ExemptAPIToken

		// 允许来源限制（配置了才生效）
		if !hasToken && !s.ipAllowed(ip) {
			s.unauthorized(w, "来源地址不在允许列表内")
			return
		}

		// 探测封禁：门槛（Basic）失败次数过多直接封 IP。
		//
		// 阈值来自 `gate.probe_ban_after / probe_ban_window / probe_ban_duration`
		// （-02：这三个字段原先零引用，实际用的是数据面的
		// `ratelimit.ban_after_hits`，而那个一旦 enabled: false 就什么也不做 ——
		// 控制台的爆破防护会静默消失）。
		if !hasToken {
			if ok, until := s.probeThrottle.allow(ip); !ok {
				s.blockedReqs.Add(1)
				w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
				s.unauthorized(w, "尝试次数过多，已临时封禁")
				return
			}
		}

		if gateNeeded(s.o.Config) && !hasToken {
			if !basicAuthOK(r, s.o.Config.Admin.Gate.Username, s.gate.passwordHash) {
				s.gateFails.Add(1)
				// 门槛失败计入封禁（与登录失败各自独立计数）
				if banned, until := s.probeThrottle.fail(ip); banned {
					recordAuth(authEvent{Action: "gate", OK: false, Remote: ip,
						Detail: fmt.Sprintf("门槛失败次数过多，封禁至 %s", until.Format(time.RFC3339))})
				}
				s.unauthorized(w, "")
				return
			}
			// 门槛通过 → 清掉该来源的失败计数
			s.probeThrottle.success(ip)
		}
		next.ServeHTTP(w, r)
	})
}

// unauthorized 统一输出 401。
//
// **不带 Server 头、不带产品特征**；realm 用中性串；响应体极简。
func (s *Server) unauthorized(w http.ResponseWriter, detail string) {
	realm := s.o.Config.Admin.Gate.Realm
	if strings.TrimSpace(realm) == "" {
		realm = defaultRealm
	}
	h := w.Header()
	h.Del("Server")
	// 用 Set 而不是直接写 map：Go 会规范化成 `Www-Authenticate` 上线，
	// 这符合 RFC 7230（头名大小写不敏感），浏览器与 curl 都正常。
	// 反过来"手工保留大写"会让 Header.Get 取不到这个头（Get 会再次规范化查询键），
	// 给后续中间件埋坑 —— 一个纯外观问题不值得换这个坑。
	h.Set("WWW-Authenticate", `Basic realm="`+realm+`", charset="UTF-8"`)
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)
	if detail != "" {
		_, _ = w.Write([]byte("401 Unauthorized\n"))
		return
	}
	_, _ = w.Write([]byte("401 Unauthorized\n"))
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
	p := strings.TrimPrefix(r.URL.Path, s.mount)
	p = strings.TrimPrefix(p, "/")
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
	base := "/"
	if s.mount != "" {
		base = s.mount + "/"
	}
	html := string(data)
	// 改写 <base href>：控制台挂在子路径下时，深链接才能找到 assets。
	html = strings.Replace(html, `<base href="/"`, `<base href="`+base+`"`, 1)
	// 同步改写前端用来算 API 前缀的 meta
	html = rewriteMetaBase(html, base)

	body := []byte(html)
	etag := `"` + shortHash(body) + "-" + shortHash([]byte(base)) + `"`
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
	//   - base-uri 'none' 尤其重要：本控制台会用 <base> 做挂载前缀，
	//     若允许注入 <base> 就能改写所有相对 URL 的指向。
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self'; font-src 'self'; "+
			"object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	_, _ = w.Write(body)
}

// rewriteMetaBase 改写 <meta name="dh-base" content="...">。
func rewriteMetaBase(html, base string) string {
	const marker = `name="dh-base"`
	i := strings.Index(html, marker)
	if i < 0 {
		return html
	}
	// 在同一标签内找 content="..."
	start := strings.Index(html[i:], `content="`)
	if start < 0 {
		return html
	}
	start += i + len(`content="`)
	end := strings.IndexByte(html[start:], '"')
	if end < 0 {
		return html
	}
	return html[:start] + base + html[start+end:]
}

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

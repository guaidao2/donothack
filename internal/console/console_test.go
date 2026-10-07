package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"donothack/internal/config"
	"donothack/internal/control"
)

func testConfig() *config.Config {
	c := config.Default()
	c.Admin.Enabled = true
	c.Admin.Addr = "127.0.0.1:18081"
	c.Admin.Username = "admin"
	c.Admin.PasswordHash = mustHash("LoginPw-2026")
	c.Admin.AllowInsecure = true
	return c
}

func mustHash(pw string) string {
	h, err := hashPassword(pw)
	if err != nil {
		panic(err)
	}
	return h
}

func newTestConsole(t *testing.T) *Server {
	t.Helper()
	cfg := testConfig()
	ctl := control.New(control.Options{Initial: &control.State{Version: "v1", DisabledRules: map[string]bool{}}})
	s, _, err := New(Options{Config: cfg, Control: ctl, Version: "test"})
	if err != nil {
		t.Fatalf("构造控制台失败：%v", err)
	}
	return s
}

// ---------------------------------------------------------------- 认证基础

func TestPasswordHashRoundTrip(t *testing.T) {
	h := mustHash("correct horse battery staple")
	if !verifyPassword(h, "correct horse battery staple") {
		t.Error("正确密码应当通过")
	}
	if verifyPassword(h, "wrong password") {
		t.Error("错误密码不该通过")
	}
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") {
		t.Errorf("哈希格式不对：%s", h)
	}
	// 同一个密码两次哈希必须不同（随机 salt）
	if h2 := mustHash("correct horse battery staple"); h == h2 {
		t.Error("相同密码两次哈希不该相同（salt 必须随机）")
	}
}

func TestVerifyPasswordRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"", "plaintext", "pbkdf2-sha256$", "pbkdf2-sha256$abc$x$y",
		"pbkdf2-sha256$600000$!!!$!!!", "bcrypt$10$abc$def",
		"pbkdf2-sha256$99999999$YWJj$YWJj", // 迭代次数离谱 → 拒绝（防 DoS）
	} {
		if verifyPassword(bad, "whatever") {
			t.Errorf("非法哈希 %q 不该通过", bad)
		}
	}
}

func TestCSRFSignature(t *testing.T) {
	secret := []byte("test-secret-0123456789abcdef")
	signed := signCSRF(secret, "tok123")
	tok, ok := checkCSRFSig(secret, signed)
	if !ok || tok != "tok123" {
		t.Fatalf("签名校验失败：ok=%v tok=%q", ok, tok)
	}
	if _, ok := checkCSRFSig(secret, "tok123.deadbeefdeadbeef"); ok {
		t.Error("伪造的签名不该通过")
	}
	if _, ok := checkCSRFSig([]byte("另一个密钥"), signed); ok {
		t.Error("换密钥后旧签名不该通过")
	}
	if _, ok := checkCSRFSig(secret, "没有点号"); ok {
		t.Error("格式不对不该通过")
	}
}

func TestCheckOrigin(t *testing.T) {
	cases := []struct {
		origin, host string
		ok           bool
	}{
		{"http://127.0.0.1:18081", "127.0.0.1:18081", true},
		{"https://console.example.com", "console.example.com", true},
		{"https://evil.example", "console.example.com", false},
		{"//evil.example", "console.example.com", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "http://"+c.host+"/api/v1/status", nil)
		r.Host = c.host
		r.Header.Set("Origin", c.origin)
		err := checkOrigin(r)
		if (err == nil) != c.ok {
			t.Errorf("Origin=%q Host=%q → err=%v，期望通过=%v", c.origin, c.host, err, c.ok)
		}
	}
	// 没有 Origin 也没有 Referer（CLI）：放行，由自定义头与 token 把关
	r := httptest.NewRequest("POST", "http://x/api", nil)
	if err := checkOrigin(r); err != nil {
		t.Errorf("无 Origin 应当放行（CLI 场景），实际 %v", err)
	}
}

// ---------------------------------------------------------------- 准入

// 控制台不再有 HTTP Basic 门槛。这条测试守两件事：
//  1. 任何响应都**不带 WWW-Authenticate** —— 带了浏览器就会弹凭据框，
//     这正是移除它的原因（运维反馈"填完还弹、怎么填都不对"）；
//  2. 认证边界仍然在 API 层：未登录一律 401 unauthenticated。
func TestNoBasicChallengeAnywhere(t *testing.T) {
	s := newTestConsole(t)
	h := s.Handler()

	paths := []string{
		"/", "/index.html", "/api/v1/status", "/api/v1/events",
		"/assets/app.js", "/不存在的路径", "/.env", "/.git/config",
		"/c/token/", "/admin", "/../../etc/passwd",
	}
	for _, p := range paths {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if wa := w.Header().Get("WWW-Authenticate"); wa != "" {
			t.Errorf("路径 %q 返回了 WWW-Authenticate: %q —— 浏览器会因此弹 Basic 框", p, wa)
		}
		// 不能带产品指纹
		if got := w.Header().Get("Server"); got != "" {
			t.Errorf("路径 %q 的响应带了 Server 头：%q", p, got)
		}
	}
}

// API 的认证边界不变：没有会话就是 401 unauthenticated。
func TestAPIStillRequiresSession(t *testing.T) {
	s := newTestConsole(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/status", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("未登录调 API 应当 401，实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unauthenticated") {
		t.Errorf("错误码应当是 API 层的 unauthenticated，实际 %s", w.Body.String())
	}
}

// allow_ips 是现在（唯一）的准入层，必须真的生效，且响应不泄露产品名。
func TestAllowIPsStillEnforced(t *testing.T) {
	cfg := testConfig()
	cfg.Admin.AllowIPs = []string{"10.9.9.9"}
	ctl := control.New(control.Options{Initial: &control.State{Version: "v1", DisabledRules: map[string]bool{}}})
	s, _, err := New(Options{Config: cfg, Control: ctl, Version: "test"})
	if err != nil {
		t.Fatalf("构造控制台失败：%v", err)
	}
	w := httptest.NewRecorder()
	// httptest 的默认来源是 192.0.2.1，不在允许列表里
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("来源不在 allow_ips 内应当 403，实际 %d", w.Code)
	}
	if strings.Contains(strings.ToLower(w.Body.String()), "donothack") {
		t.Errorf("403 响应体泄露了产品名：%s", w.Body.String())
	}
}

// ---------------------------------------------------------------- 写防护

// 写操作必须四道全过：会话 + 自定义头 + Origin + CSRF。
func TestWriteRequiresAllFourGuards(t *testing.T) {
	s := newTestConsole(t)
	id, csrf, err := s.session.create("admin", "127.0.0.1", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signed := signCSRF(s.secret, csrf)

	cases := []struct {
		name    string
		headers map[string]string
		cookie  bool
		want    string
	}{
		{"缺全部", nil, true, "missing_console_header"},
		{"只有自定义头", map[string]string{consoleHeader: "1"}, true, "missing_csrf"},
		{"有头与错 CSRF", map[string]string{consoleHeader: "1", csrfHeader: "错的"}, true, "csrf_mismatch"},
		{"全对", map[string]string{consoleHeader: "1", csrfHeader: csrf}, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("PUT", "http://127.0.0.1:18081/api/v1/block-page", nil)
			r.Host = "127.0.0.1:18081"
			if c.cookie {
				r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
				r.AddCookie(&http.Cookie{Name: csrfCookie, Value: signed})
			}
			for k, v := range c.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			if ok := s.requireWrite(w, r); ok != (c.want == "") {
				t.Fatalf("requireWrite=%v，期望 %v（响应 %s）", ok, c.want == "", w.Body.String())
			}
			if c.want != "" && !strings.Contains(w.Body.String(), c.want) {
				t.Errorf("错误码应包含 %q，实际 %s", c.want, w.Body.String())
			}
		})
	}
}

// 跨站 Origin 必须被拒（浏览器会自动带 cookie，这是 CSRF 的入口）。
func TestWriteRejectsCrossOrigin(t *testing.T) {
	s := newTestConsole(t)
	id, csrf, _ := s.session.create("admin", "127.0.0.1", "test", time.Hour)
	r := httptest.NewRequest("PUT", "http://127.0.0.1:18081/api/v1/block-page", nil)
	r.Host = "127.0.0.1:18081"
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: id})
	r.AddCookie(&http.Cookie{Name: csrfCookie, Value: signCSRF(s.secret, csrf)})
	r.Header.Set(consoleHeader, "1")
	r.Header.Set(csrfHeader, csrf)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	if s.requireWrite(w, r) {
		t.Error("跨站 Origin 必须被拒")
	}
	if !strings.Contains(w.Body.String(), "bad_origin") {
		t.Errorf("错误码应为 bad_origin，实际 %s", w.Body.String())
	}
}

func TestClientIPAndAllowIPs(t *testing.T) {
	s := newTestConsole(t)
	s.o.Config.Admin.AllowIPs = []string{"10.0.0.0/8", "192.168.1.5"}
	if !s.ipAllowed("10.1.2.3") || !s.ipAllowed("192.168.1.5") {
		t.Error("允许列表内的地址应当放行")
	}
	if s.ipAllowed("8.8.8.8") {
		t.Error("允许列表外的地址应当被拒")
	}
	s.o.Config.Admin.AllowIPs = nil
	if !s.ipAllowed("8.8.8.8") {
		t.Error("没配允许列表时不限制来源")
	}
}

func TestAllowIPsAppliesEvenWithValidToken(t *testing.T) {
	s := newTestConsole(t)
	s.o.Config.Admin.APIToken = "secret-token-123456"
	s.o.Config.Admin.AllowIPs = []string{"10.9.9.9"}

	// allow_ips 是**网络边界**：来源不在列表里就是 403，即使 token 正确。
	// （曾经 token 能顺带免掉白名单，而配置里那个开关写着"只免门槛"，
	// 名不副实；现在只有一条规则：白名单对所有人一视同仁。）
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	r.Header.Set(tokenHeader, "secret-token-123456")
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("来源不在 allow_ips 内应当 403（与 token 无关），实际 %d", w.Code)
	}

	// 写操作：token 路径要求自定义头（没有浏览器上下文，不需要 CSRF）
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("PUT", "/api/v1/block-page", nil)
	r2.Header.Set(tokenHeader, "secret-token-123456")
	if s.requireWrite(w2, r2) {
		t.Error("token 路径也必须带自定义头")
	}
	r2.Header.Set(consoleHeader, "1")
	if !s.requireWrite(httptest.NewRecorder(), r2) {
		t.Error("带 token + 自定义头应当通过")
	}
}

// 带 API token 仍然需要会话或 token 才能调 API（token 不是万能通行证）。
func TestAPITokenStillNeedsValidToken(t *testing.T) {
	s := newTestConsole(t)
	s.o.Config.Admin.APIToken = "secret-token-123456"

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	r.Header.Set(tokenHeader, "错的-token")
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("token 不对应当被 API 层拒（401），实际 %d", w.Code)
	}
}

func TestSameHost(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"example.com", "example.com", true},
		{"example.com:443", "example.com:18081", true},
		{"EXAMPLE.com", "example.com", true},
		{"evil.com", "example.com", false},
	}
	for _, c := range cases {
		if got := sameHost(c.a, c.b); got != c.want {
			t.Errorf("sameHost(%q,%q)=%v，期望 %v", c.a, c.b, got, c.want)
		}
	}
}

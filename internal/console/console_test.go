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
	c.Admin.Gate.Enabled = true
	c.Admin.Gate.Mode = "basic"
	c.Admin.Gate.Realm = "Restricted"
	c.Admin.Gate.Username = "gatekeeper"
	c.Admin.Gate.PasswordHash = mustHash("GatePw-2026")
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

// ---------------------------------------------------------------- 门槛

// 门槛最要紧的判据：**所有路径统一 401，不区分是否存在**。
// 用 404 区分会立刻把控制台从一堆端口里暴露出来。
func TestGateReturns401OnEveryPath(t *testing.T) {
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
		if w.Code != http.StatusUnauthorized {
			t.Errorf("路径 %q 应返回 401，实际 %d", p, w.Code)
		}
		// 不能带产品指纹
		if got := w.Header().Get("Server"); got != "" {
			t.Errorf("路径 %q 的响应带了 Server 头：%q", p, got)
		}
		wa := w.Header().Get("WWW-Authenticate")
		if !strings.Contains(wa, `Basic realm="Restricted"`) {
			t.Errorf("路径 %q 的 realm 不对：%q", p, wa)
		}
		if strings.Contains(strings.ToLower(w.Body.String()), "donothack") &&
			!strings.Contains(w.Body.String(), "401") {
			t.Errorf("路径 %q 的 401 响应体泄露了产品名", p)
		}
	}
}

func TestGateAcceptsCorrectBasic(t *testing.T) {
	s := newTestConsole(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	r.SetBasicAuth("gatekeeper", "GatePw-2026")
	s.Handler().ServeHTTP(w, r)
	// 过了门槛但没登录 → API 层 401（不是门槛的 401）
	if w.Code != http.StatusUnauthorized {
		t.Errorf("过门槛未登录应当被 API 拒绝，实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "unauthenticated") &&
		!strings.Contains(w.Body.String(), "需要先登录") {
		t.Errorf("应当是 API 层的未登录错误，实际 %s", w.Body.String())
	}
}

func TestGateRejectsWrongBasic(t *testing.T) {
	s := newTestConsole(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.SetBasicAuth("gatekeeper", "错的")
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("门槛凭据错应当 401，实际 %d", w.Code)
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

func TestAPITokenSkipsGateButRequiresHeader(t *testing.T) {
	s := newTestConsole(t)
	s.o.Config.Admin.APIToken = "secret-token-123456"
	// token 免除门槛**必须显式开启**（-04：
	// 原先这个开关没人读，等于永远免门槛、免白名单、免限速）。
	s.o.Config.Admin.Gate.ExemptAPIToken = true

	// 带 token 不需要门槛 Basic
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	r.Header.Set(tokenHeader, "secret-token-123456")
	s.Handler().ServeHTTP(w, r)
	if w.Code == http.StatusUnauthorized {
		t.Error("带合法 API token 不该被门槛拦住")
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

	// 错 token 无效
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.Header.Set(tokenHeader, "错的")
	w3 := httptest.NewRecorder()
	s.Handler().ServeHTTP(w3, r3)
	if w3.Code != http.StatusUnauthorized {
		t.Errorf("错 token 应当被门槛拦，实际 %d", w3.Code)
	}
}

// 关掉 `gate.exempt_api_token` 后，**即使 token 正确也必须过门槛**。
//
// 这是-04 的回归：token 原先是一条约不到的硬通道，
// 而它同时免掉 IP 白名单、限速与探测封禁。
func TestAPITokenExemptionCanBeDisabled(t *testing.T) {
	s := newTestConsole(t)
	s.o.Config.Admin.APIToken = "secret-token-123456"
	s.o.Config.Admin.Gate.ExemptAPIToken = false // 显式关闭

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/status", nil)
	r.Header.Set(tokenHeader, "secret-token-123456")
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("关掉豁免后，带 token 也必须过门槛（401），实际 %d", w.Code)
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

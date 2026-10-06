package console

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 本文件是控制台的认证与防护。
//
// 两层准入（docs/CONSOLE.md §3.1，判据见项目 key 记忆）：
//
//	第一层 HTTP Basic —— **不是认证边界**，只是"不让扫描器看见门"。
//	    未过门槛时，监听端口上**所有路径统一返回 401，不区分路径是否存在**。
//	    绝不能只对 `/` 与已知 API 要 Basic 而让其他路径 404 ——
//	    401/404 的差异本身就是指纹，等于告诉扫描器"这个端口有什么"。
//	第二层 表单登录 + 会话 —— 这才是真正的认证。
//
// 其余要点：
//   - 门槛凭据与登录账号**分开**：门槛凭据只解锁登录页，不授予任何权限，
//     可单独轮换、可交给运维同事。
//   - 401 响应不带 `Server` 头、不带产品特征；realm 用中性串（默认 Restricted）。
//   - 门槛失败与登录失败合并计入封禁；另加探测封禁（默认 60s 内 20 次 → 封 15 分钟）。
//   - 写操作必须三重防护：CSRF token + 自定义头 + Origin 校验。
//     只靠 Basic/会话 cookie 不行 —— 浏览器会自动带上凭据。

const (
	// 门槛的 Basic realm 默认值：中性，不暴露产品。
	defaultRealm = "Restricted"
	// 会话 cookie 名。
	sessionCookie = "donothack_session"
	// CSRF cookie 名（前端已按这个名字对接）。
	csrfCookie = "donothack_csrf"
	// CSRF 头名。
	csrfHeader = "X-Donothack-CSRF"
	// 写操作必须带的自定义头（跨站请求带不上自定义头，这是最简单有效的一道）。
	consoleHeader = "X-Donothack-Console"
	// API token 头（CLI 用，可跳过门槛）。
	tokenHeader = "X-Donothack-Token"

	// PBKDF2 参数。60 万次是 OWASP 对 PBKDF2-HMAC-SHA256 的建议量级。
	pbkdf2Iterations = 600000
	pbkdf2KeyLen     = 32
	saltLen          = 16
)

// hashPassword 生成 `pbkdf2-sha256$迭代次数$salt$hash` 形式的密文。
func hashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk)), nil
}

// verifyPassword 校验密码。**用常数时间比较**，避免按字节比较泄露信息。
func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 || iter > 10_000_000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// generatePassword 生成一个可读的随机初始密码。
//
// 用易读字符集（去掉 0/O/1/l/I 这类易混字符）：这个密码要人工抄进浏览器，
// 抄错一次就可能被当成"认证失败"计入封禁。
func generatePassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const n = 20
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out), nil
}

// ---------------------------------------------------------------- 会话

type session struct {
	User    string
	Expires time.Time
	// CSRF 与创建时间
	CSRF string
	// Remote 与 UA 用于审计（不做绑定：办公网 IP 变动很常见，绑了会天天掉线）
	Remote string
	UA     string
}

type sessionStore struct {
	mu       sync.RWMutex
	m        map[string]*session
	capacity int
}

func newSessionStore(capacity int) *sessionStore {
	if capacity <= 0 {
		capacity = 256
	}
	return &sessionStore{m: make(map[string]*session, 16), capacity: capacity}
}

func (s *sessionStore) create(user, remote, ua string, ttl time.Duration) (id, csrf string, err error) {
	idb := make([]byte, 32)
	cb := make([]byte, 32)
	if _, err = rand.Read(idb); err != nil {
		return "", "", err
	}
	if _, err = rand.Read(cb); err != nil {
		return "", "", err
	}
	id = base64.RawURLEncoding.EncodeToString(idb)
	csrf = base64.RawURLEncoding.EncodeToString(cb)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) >= s.capacity {
		s.evictLocked()
	}
	s.m[id] = &session{User: user, Expires: time.Now().Add(ttl), CSRF: csrf, Remote: remote, UA: ua}
	return id, csrf, nil
}

func (s *sessionStore) get(id string) (*session, bool) {
	s.mu.RLock()
	sess, ok := s.m[id]
	s.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(sess.Expires) {
		s.mu.Lock()
		delete(s.m, id)
		s.mu.Unlock()
		return nil, false
	}
	return sess, true
}

// touch 延长空闲超时（滑动过期）。
func (s *sessionStore) touch(id string, ttl time.Duration) {
	s.mu.Lock()
	if sess, ok := s.m[id]; ok {
		sess.Expires = time.Now().Add(ttl)
	}
	s.mu.Unlock()
}

func (s *sessionStore) drop(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// dropAll 注销全部会话（改密码后调用：旧会话必须立刻失效）。
func (s *sessionStore) dropAll() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.m)
	s.m = make(map[string]*session, 16)
	return n
}

func (s *sessionStore) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m)
}

// evictLocked 淘汰最快过期的会话；全都没过期时丢一个任意的（保证有界）。
func (s *sessionStore) evictLocked() {
	var victim string
	var earliest time.Time
	for id, sess := range s.m {
		if victim == "" || sess.Expires.Before(earliest) {
			victim, earliest = id, sess.Expires
		}
	}
	if victim != "" {
		delete(s.m, victim)
	}
}

// cleanup 定期清理过期会话。
func (s *sessionStore) cleanup() {
	now := time.Now()
	s.mu.Lock()
	for id, sess := range s.m {
		if now.After(sess.Expires) {
			delete(s.m, id)
		}
	}
	s.mu.Unlock()
}

// ---------------------------------------------------------------- CSRF 与来源校验

// signCSRF 用 HMAC 给 token 签名，做成"双提交 + 签名"：
// 即使攻击者能写 cookie（子域接管等），没有密钥也造不出合法 token。
func signCSRF(secret []byte, token string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token))
	return token + "." + hex.EncodeToString(mac.Sum(nil))[:16]
}

func checkCSRFSig(secret []byte, signed string) (string, bool) {
	i := strings.LastIndexByte(signed, '.')
	if i <= 0 {
		return "", false
	}
	token, sig := signed[:i], signed[i+1:]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token))
	want := hex.EncodeToString(mac.Sum(nil))[:16]
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", false
	}
	return token, true
}

// checkOrigin 校验写请求的来源。
//
// 策略：有 Origin 就必须与 Host 同源；没有 Origin 时要求有自定义头
// （浏览器发起的跨站表单请求会带 Origin，但同站的部分老浏览器不带；
// 自定义头是跨站带不上的，两者互补）。
func checkOrigin(r *http.Request) error {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		referer := strings.TrimSpace(r.Header.Get("Referer"))
		if referer == "" {
			return nil // 非浏览器客户端（CLI），由自定义头与 token 把关
		}
		origin = referer
	}
	// 解析出 host 部分
	h := origin
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	reqHost := r.Host
	if !sameHost(h, reqHost) {
		return fmt.Errorf("来源 %q 与本站 %q 不同源", h, reqHost)
	}
	return nil
}

// sameHost 比较主机名（忽略端口差异，容忍反代改端口）。
func sameHost(a, b string) bool {
	strip := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		if i := strings.LastIndexByte(s, ':'); i > 0 && !strings.Contains(s[i+1:], "]") {
			if _, err := strconv.Atoi(s[i+1:]); err == nil {
				return s[:i]
			}
		}
		return s
	}
	return strip(a) == strip(b)
}

// isWriteMethod 判断是否写操作。
func isWriteMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// basicAuthOK 校验门槛凭据。
func basicAuthOK(r *http.Request, wantUser, wantHash string) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	// 用户名也要常数时间比：否则能通过响应时间枚举用户名是否存在。
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(wantUser)) == 1
	// 注意：**无论用户名对不对都跑一次 PBKDF2**，避免"用户名错马上就返回"
	// 造成的时间侧信道。这里用密码校验的结果与用户名校验结果相与。
	passOK := verifyPassword(wantHash, pass)
	return userOK && passOK
}

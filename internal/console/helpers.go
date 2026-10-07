package console

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// hashState 持有一份可轮换的口令哈希（登录口令、TOTP 密钥都用它）。
//
// 单独包一层（而不是直接读配置）是因为这些值要能**在不重启的情况下轮换**。
type hashState struct {
	mu           sync.RWMutex
	passwordHash string
}

func (g *hashState) set(hash string) {
	g.mu.Lock()
	g.passwordHash = hash
	g.mu.Unlock()
}

func (g *hashState) get() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.passwordHash
}

// ---------------------------------------------------------------- 响应

// apiError 是统一的错误响应体。
//
// code 是稳定可判断的机器码；message 给人看；detail 放细节（**不含 payload**）。
type apiError struct {
	Error errBody `json:"error"`
}

type errBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	// **保持 HTML 转义开启**（原先显式 SetEscapeHTML(false)）。
	//
	// 关掉它的唯一好处是响应体好看一点，而代价是：任何进了事件的用户可控字段
	// （URL、UA、payload）都会原样带着 `<script>` 出现在响应里。
	// 我们已经用 nosniff + 前端只走 textContent 挡了两道，但没有理由再自己拆一道
	// —— 转义后的 `\u003c` 在 JS 里解码结果完全一样，前端感知不到差别。
	_ = enc.Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, msg, detail string) {
	writeJSON(w, status, apiError{Error: errBody{Code: code, Message: msg, Detail: detail}})
}

// writeOK 是写操作的成功响应：带上新版本与警告，
// 让前端能立刻告诉运维"这次改动影响到了什么"。
type okResponse struct {
	OK              bool     `json:"ok"`
	SnapshotVersion string   `json:"snapshot_version,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	// PasswordHash 只在"改登录口令"这一个响应里出现，方便运维把它写进配置。
	// 其余接口一律不回显任何凭据（见 api.go 的 /config 脱敏）。
	PasswordHash string `json:"password_hash,omitempty"`
}

// ---------------------------------------------------------------- 请求

// decodeJSON 读取 JSON 请求体，**限制大小**（控制台也可能被塞大 body）。
func decodeJSON(r *http.Request, v any) error {
	const maxBody = 1 << 20 // 1 MiB：规则片段与拦截页模板都远小于此
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return errTooLarge
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

type sizeError struct{}

func (sizeError) Error() string { return "请求体过大（上限 1 MiB）" }

var errTooLarge = sizeError{}

// ---------------------------------------------------------------- 杂项

func readAll(f io.Reader, size int64) ([]byte, error) {
	buf := make([]byte, 0, size)
	tmp := make([]byte, 32<<10)
	for {
		n, err := f.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// shortHash 返回内容的前 16 位十六进制哈希，用于 ETag 与版本号。
func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

// contentTypeOf 按扩展名给 MIME。
//
// 手写而不是用 mime.TypeByExtension：后者在 Windows 上会读注册表，
// 不同机器给的结果可能不一样（实测 .js 在一台机器上是 text/plain）。
// MIME 给错会让浏览器拒绝执行 ES module。
func contentTypeOf(p string) string {
	switch {
	case strings.HasSuffix(p, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(p, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(p, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(p, ".json"):
		return "application/json; charset=utf-8"
	case strings.HasSuffix(p, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(p, ".png"):
		return "image/png"
	case strings.HasSuffix(p, ".jpg"), strings.HasSuffix(p, ".jpeg"):
		return "image/jpeg"
	case strings.HasSuffix(p, ".ico"):
		return "image/x-icon"
	case strings.HasSuffix(p, ".woff2"):
		return "font/woff2"
	case strings.HasSuffix(p, ".map"):
		return "application/json; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// nowISO 返回带时区的 RFC3339 时间。
func nowISO() string { return time.Now().Format(time.RFC3339) }

// queryInt 读整数查询参数。
func queryInt(r *http.Request, key string, def int) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return def
	}
	n := 0
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return def
		}
		n = n*10 + int(v[i]-'0')
		if n > 1_000_000 {
			return def
		}
	}
	return n
}

package console

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"donothack/internal/control"
)

// 拦截页的**可视化预览**通道。
//
// 为什么要绕一道票据：控制台不允许把模板 HTML 直接塞进当前文档（禁 innerHTML 是硬门禁），
// 所以它要嵌在 iframe 里；而 iframe 只能发 GET、带不上 CSRF 头，permissions 上也没法
// 走写接口。于是：POST 一次换一个短时效票据 → GET /block-page/preview/<token> 取那份
// 渲染好的 HTML，响应**自带沙箱 CSP**（脚本一律不执行、外部资源一律不加载）。
//
// 上限是刻意的（每一项资源都必须有界）：条数 16、单份 256 KiB、TTL 5 分钟。
const (
	blockPreviewTTL     = 5 * time.Minute
	blockPreviewMax     = 16
	blockPreviewMaxBody = 256 << 10
)

type blockPreviewItem struct {
	html    string
	expires time.Time
}

type blockPreviewStore struct {
	mu    sync.Mutex
	items map[string]blockPreviewItem
	order []string // 插入顺序，超上限时淘汰最旧的
}

func newBlockPreviewStore() *blockPreviewStore {
	return &blockPreviewStore{items: make(map[string]blockPreviewItem, blockPreviewMax)}
}

// put 存一份渲染结果，返回票据。超过单份上限时返回 false（不静默截断 —— 截断的预览会骗人）。
func (s *blockPreviewStore) put(html string) (string, bool) {
	if html == "" || len(html) > blockPreviewMaxBody {
		return "", false
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", false
	}
	token := hex.EncodeToString(raw)

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.items {
		if now.After(v.expires) {
			delete(s.items, k)
		}
	}
	for len(s.order) >= blockPreviewMax {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.items, oldest)
	}
	s.items[token] = blockPreviewItem{html: html, expires: now.Add(blockPreviewTTL)}
	s.order = append(s.order, token)
	return token, true
}

func (s *blockPreviewStore) get(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[token]
	if !ok {
		return "", false
	}
	if time.Now().After(item.expires) {
		delete(s.items, token)
		return "", false
	}
	return item.html, true
}

// handleBlockPagePreviewTicket 颁发预览票据（POST /api/v1/block-page/preview/ticket）。
func (s *Server) handleBlockPagePreviewTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 POST", "")
		return
	}
	if !s.requireWrite(w, r) {
		return
	}
	var req struct {
		HTML     string `json:"html"`
		Method   string `json:"method"`
		Host     string `json:"host"`
		Path     string `json:"path"`
		Category string `json:"category"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
		return
	}
	snap := s.o.Control.Snapshot()
	if snap == nil {
		s.writeError(w, http.StatusServiceUnavailable, "no_snapshot", "控制面尚未初始化", "")
		return
	}
	html, err := control.PreviewBlockPageHTML(snap, req.HTML, control.SampleRequest{
		Method: req.Method, Host: req.Host, Path: req.Path, Category: req.Category,
	})
	if err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "invalid_template", "模板编译失败", err.Error())
		return
	}
	token, ok := s.blockPreview.put(html)
	if !ok {
		s.writeError(w, http.StatusUnprocessableEntity, "preview_too_large",
			"渲染结果为空或过大，无法可视化预览", "")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"token":      token,
		"expires_in": int(blockPreviewTTL.Seconds()),
	})
}

// handleBlockPagePreviewRender 取回渲染结果（GET /api/v1/block-page/preview/<token>）。
//
// 响应带沙箱 CSP：模板里的脚本不执行、外部资源不加载，只放行内联样式
// （拦截页模板就是内联 <style>）。所以即使模板被人塞了 <script>，这里也只是显示出来。
func (s *Server) handleBlockPagePreviewRender(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "必须用 GET", "")
		return
	}
	if !s.requireRead(w, r) {
		return
	}
	token := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/block-page/preview/"), "/")
	if token == "" || strings.Contains(token, "/") {
		s.writeError(w, http.StatusNotFound, "not_found", "预览不存在", "")
		return
	}
	html, ok := s.blockPreview.get(token)
	if !ok {
		s.writeError(w, http.StatusNotFound, "not_found", "预览已过期，请重新点一次预览", "")
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy",
		"sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	// 明确允许被同源页面嵌（控制台只在内嵌预览里用它；默认的 DENY 是给 SPA 外壳设的）。
	h.Set("X-Frame-Options", "SAMEORIGIN")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, html)
}

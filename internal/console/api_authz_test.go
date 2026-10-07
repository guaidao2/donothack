package console

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 所有 /api/v1/* 默认必须要求认证，只有显式白名单例外。
//
// 存在的理由：`GET /api/v1/engine` 曾经漏挂会话校验 —— 同一中间件下其余端点全部 401，
// 只有它把引擎参数（mode / inbound_anomaly_threshold / 阈值 / 封禁时长）返回给匿名请求。
// 这类"新增路由忘了挂认证"的缺陷不会自己暴露，所以用遍历覆盖住：
// 路由清单由 routes() 自动记录，新增路由自动进入本测试。
func TestAllAPIRoutesRequireAuth(t *testing.T) {
	s := newTestConsole(t)
	if len(apiRoutePaths) == 0 {
		t.Fatal("没记录到任何 /api/v1/* 路由：routes() 里的记录钩子坏了")
	}
	// 唯一允许匿名的端点：登录本身。
	allow := map[string]bool{"/api/v1/login": true}

	// GET 与 POST 都要 401：以前 POST-only 的端点未认证时先回 405，
	// 现在中间件在方法分发之前就拦下来，不会再泄露"这个端点存在且收什么方法"。
	for _, p := range apiRoutePaths {
		if allow[p] {
			continue
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(method, "http://127.0.0.1:18081"+p, nil)
			req.Host = "127.0.0.1:18081"
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s 未认证应返回 401，实际 %d（是不是绕过中间件了？）",
					method, p, rec.Code)
			}
		}
	}
}

package rulessync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 只打 tag、没发 Release 的状态必须能被同步到。
//
// 这是真实踩到的场景：仓库里 v1.3.0 打了 tag 但没发 Release，
// 若默认解析只看 /releases/latest，就会同步到 v1.2.0 的规则集 ——
// 用户以为更新了，其实拿回来的是旧的、能被绕过的那一套。
func TestLatestTagPrefersNewestTagOverRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/tags":
			_ = json.NewEncoder(w).Encode([]map[string]string{
				{"name": "v1.1.0"}, {"name": "v1.3.0"}, {"name": "v1.2.0"}, {"name": "not-a-version"},
			})
		case "/repos/o/r/releases/latest":
			_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": "v1.2.0"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	got, err := LatestTag(context.Background(), srv.Client(), srv.URL+"/repos/o/r/contents/rules")
	if err != nil {
		t.Fatalf("LatestTag 失败：%v", err)
	}
	if got != "v1.3.0" {
		t.Fatalf("应取最新 tag v1.3.0，实得 %q", got)
	}
}

// tags 拿不到时退回最新发布。
func TestLatestTagFallsBackToRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/o/r/releases/latest" {
			_ = json.NewEncoder(w).Encode(map[string]string{"tag_name": "v9.9.9"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	got, err := LatestTag(context.Background(), srv.Client(), srv.URL+"/repos/o/r/contents/rules")
	if err != nil {
		t.Fatalf("LatestTag 失败：%v", err)
	}
	if got != "v9.9.9" {
		t.Fatalf("应退回最新发布 v9.9.9，实得 %q", got)
	}
}

package rulessync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"donothack/internal/rules"
)

// loadVersion 取某目录的规则集指纹，用来断言"有没有被改动"。
func loadVersion(dir string) (string, error) {
	rs, err := rules.LoadDir(rules.DefaultOptions(), dir, []string{"*.yaml"})
	if err != nil {
		return "", err
	}
	return rs.Version, nil
}

// 用真实出厂规则文件当素材，避免测试里手写 YAML 结构漂移。
func realRule(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "rules", name))
	if err != nil {
		t.Fatalf("读出厂规则失败：%v", err)
	}
	return data
}

func writeDir(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatalf("写文件失败：%v", err)
		}
	}
	return dir
}

// 起一个"远端"：/list 返回目录清单，/f/<name> 返回文件内容。
func fakeRemote(t *testing.T, files map[string][]byte, broken bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	mux.HandleFunc("/f/", func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		data, ok := files[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(data)
	})
	mux.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		type item struct {
			Name        string `json:"name"`
			DownloadURL string `json:"download_url"`
		}
		var items []item
		for name := range files {
			items = append(items, item{Name: name, DownloadURL: srv.URL + "/f/" + name})
		}
		if broken {
			// 越界文件名必须被忽略，不能写到规则目录之外
			items = append(items, item{Name: "../evil.yaml", DownloadURL: srv.URL + "/f/x"})
			items = append(items, item{Name: "notes.txt", DownloadURL: srv.URL + "/f/x"})
		}
		_ = json.NewEncoder(w).Encode(items)
	})
	return srv
}

func TestFetchAndApplyReplacesAfterValidation(t *testing.T) {
	next := map[string][]byte{"60-webshell.yaml": realRule(t, "60-webshell.yaml")}
	srv := fakeRemote(t, next, true)
	defer srv.Close()

	files, _, err := Fetch(context.Background(), Source{BaseURL: srv.URL + "/list"}, srv.Client())
	if err != nil {
		t.Fatalf("Fetch 失败：%v", err)
	}
	if len(files) != 1 {
		t.Fatalf("只应收到 1 个规则文件，实得 %d（越界文件名与 .txt 必须被忽略）", len(files))
	}

	dir := writeDir(t, map[string][]byte{"00-protocol.yaml": realRule(t, "00-protocol.yaml")})
	before, err := loadVersion(dir)
	if err != nil {
		t.Fatalf("初始目录不可加载：%v", err)
	}
	res, err := Apply(dir, files)
	if err != nil {
		t.Fatalf("Apply 失败：%v", err)
	}
	if res.Skipped || res.FromVersion == res.ToVersion {
		t.Fatalf("应发生替换：%+v", res)
	}
	after, err := loadVersion(dir)
	if err != nil {
		t.Fatalf("替换后目录不可加载：%v", err)
	}
	if after != res.ToVersion || after == before {
		t.Fatalf("替换后指纹不符：before=%s after=%s res.To=%s", before, after, res.ToVersion)
	}
	if _, err := os.Stat(filepath.Join(dir, "00-protocol.yaml")); !os.IsNotExist(err) {
		t.Fatal("旧文件应已被移走")
	}
	if _, err := os.Stat(filepath.Join(dir, "60-webshell.yaml")); err != nil {
		t.Fatal("新文件应已就位")
	}
}

func TestApplySkipsWhenFingerprintSame(t *testing.T) {
	files := map[string][]byte{"60-webshell.yaml": realRule(t, "60-webshell.yaml")}
	dir := writeDir(t, map[string][]byte{"60-webshell.yaml": realRule(t, "60-webshell.yaml")})
	res, err := Apply(dir, files)
	if err != nil {
		t.Fatalf("Apply 失败：%v", err)
	}
	if !res.Skipped {
		t.Fatalf("指纹相同时应跳过，实得 %+v", res)
	}
}

func TestApplyKeepsOldRulesWhenNewSetInvalid(t *testing.T) {
	dir := writeDir(t, map[string][]byte{"00-protocol.yaml": realRule(t, "00-protocol.yaml")})
	before, err := loadVersion(dir)
	if err != nil {
		t.Fatalf("初始目录不可加载：%v", err)
	}
	// 缺正负样本 / 未知算子都会被加载器拒绝
	bad := map[string][]byte{"99-broken.yaml": []byte("version: 1\nrules:\n  - id: BROKEN-0001\n    category: sqli\n    score: 5\n    message: x\n    targets:\n      - collection: ARGS\n    operator:\n      name: pm\n")}
	if _, err := Apply(dir, bad); err == nil {
		t.Fatal("新规则集非法时必须报错")
	}
	after, err := loadVersion(dir)
	if err != nil {
		t.Fatalf("原规则被破坏了：%v", err)
	}
	if after != before {
		t.Fatalf("非法集合不得改动本地：before=%s after=%s", before, after)
	}
	if _, err := os.Stat(filepath.Join(dir, "00-protocol.yaml")); err != nil {
		t.Fatal("原文件应原样保留")
	}
	if _, err := os.Stat(filepath.Join(dir, "99-broken.yaml")); !os.IsNotExist(err) {
		t.Fatal("非法文件不得落进规则目录")
	}
}

func TestFetchRejectsBadInput(t *testing.T) {
	if _, _, err := Fetch(context.Background(), Source{BaseURL: "ftp://example.com/rules"}, nil); err == nil {
		t.Fatal("非 http(s) 地址必须被拒绝")
	}
	srv := fakeRemote(t, map[string][]byte{}, true)
	defer srv.Close()
	if _, _, err := Fetch(context.Background(), Source{BaseURL: srv.URL + "/list"}, srv.Client()); err == nil {
		t.Fatal("清单里没有 .yaml 时必须报错（不能当成空集合同步下去）")
	}
}

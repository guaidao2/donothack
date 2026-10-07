// Package rulessync 从远端取回一份规则集，校验通过后才替换本地规则目录。
//
// 设计取舍（有意保持简单）：
//   - 只做**手动**同步（CLI / 控制台按钮触发），不做定时自动拉取。
//   - 不引入签名体系：规则是数据、不能执行代码，最坏后果是"检测失效或误报"，
//     而不是被拿下机器；与其管理一把长期私钥，不如把力气花在下面这道闸门上。
//   - **闸门**：新规则必须先通过正式加载器的全部校验（含每条规则的正负样本自测），
//     通过才替换；任何一步失败都保持原状并把错误交回调用方。
//     没有这道闸门，一次手滑的提交就能让线上"零规则在跑"，而界面看着一切正常。
package rulessync

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"donothack/internal/rules"
)

// DefaultSource 是默认的目录清单地址（GitHub contents API 的 rules 目录）。
const DefaultSource = "https://api.github.com/repos/guaidao2/donothack/contents/rules"

// maxFileBytes 限制单个规则文件大小：规则是文本，正常几 KB。
// 没有上限的下载等于给远端一个写满磁盘的机会。
const maxFileBytes = 1 << 20

// Source 描述从哪里取。
type Source struct {
	// BaseURL 是目录清单地址：返回一个 JSON 数组，每项含 name 与 download_url。
	// 用这个形状是为了同时兼容 GitHub contents API 和内网镜像。
	BaseURL string
	// Ref 是版本选择：留空表示默认分支，也可以是 tag / commit。
	// 建议固定到 tag —— 默认分支上随时可能是半成品提交。
	Ref string
}

// Result 是一次同步的结果，供审计与界面展示。
type Result struct {
	FromVersion string // 替换前的规则集指纹
	ToVersion   string // 替换后的规则集指纹（未替换时与 From 相同）
	Files       int    // 文件数
	Source      string // 实际取回的地址（含 ref）
	Skipped     bool   // 指纹相同，未做替换
}

type remoteFile struct {
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
}

// Fetch 取回目录清单与每个文件的内容。**只读远端，不碰本地磁盘。**
func Fetch(ctx context.Context, s Source, hc *http.Client) (map[string][]byte, string, error) {
	base := strings.TrimSpace(s.BaseURL)
	if base == "" {
		base = DefaultSource
	}
	if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://") {
		return nil, "", fmt.Errorf("同步地址必须是 http(s): %s", base)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	ref := strings.TrimSpace(s.Ref)
	listURL := base
	if ref != "" {
		listURL += "?ref=" + ref
	}

	body, err := get(ctx, hc, listURL)
	if err != nil {
		return nil, "", fmt.Errorf("取目录清单失败：%w", err)
	}
	var items []remoteFile
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, "", fmt.Errorf("目录清单不是预期的 JSON 数组：%w", err)
	}

	out := make(map[string][]byte, len(items))
	for _, it := range items {
		name := strings.TrimSpace(it.Name)
		// 只收规则文件，且不接受路径分隔符 —— 避免远端用文件名写到目录外。
		if name == "" || strings.ContainsAny(name, `/\`) || !strings.HasSuffix(name, ".yaml") {
			continue
		}
		if it.DownloadURL == "" {
			continue
		}
		data, err := get(ctx, hc, it.DownloadURL)
		if err != nil {
			return nil, "", fmt.Errorf("取 %s 失败：%w", name, err)
		}
		out[name] = data
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("清单里没有任何 .yaml 规则文件（%s）", listURL)
	}
	return out, listURL, nil
}

// Apply 把取回的规则写进 rulesDir，并在替换前后各校验一次。
//
// 顺序刻意是"先落地到临时目录 → 校验 → 备份旧文件 → 就位"：
// 任何一步失败都恢复原状，调用方拿到的目录要么是旧的、要么是校验通过的新集合。
func Apply(rulesDir string, files map[string][]byte) (Result, error) {
	res := Result{Files: len(files)}
	if rulesDir == "" {
		return res, fmt.Errorf("规则目录不能为空")
	}
	if len(files) == 0 {
		return res, fmt.Errorf("没有要写入的规则文件")
	}

	// 1) 当前指纹（目录为空时按"无规则集"处理，不算失败）
	cur, err := rules.LoadDir(rules.DefaultOptions(), rulesDir, []string{"*.yaml"})
	if err != nil {
		return res, fmt.Errorf("当前规则集无法加载，先修好它再同步：%w", err)
	}
	res.FromVersion = cur.Version

	// 2) 落到临时目录并校验
	stage, err := os.MkdirTemp(filepath.Dir(filepath.Clean(rulesDir)), ".rulesync-*")
	if err != nil {
		return res, fmt.Errorf("建临时目录失败：%w", err)
	}
	defer os.RemoveAll(stage)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(stage, name), data, 0o644); err != nil {
			return res, fmt.Errorf("写入 %s 失败：%w", name, err)
		}
	}
	next, err := rules.LoadDir(rules.DefaultOptions(), stage, []string{"*.yaml"})
	if err != nil {
		return res, fmt.Errorf("新规则集没通过校验，已保持原状：%w", err)
	}
	res.ToVersion = next.Version
	res.Source = fmt.Sprintf("%d 个文件", len(files))

	// 3) 指纹相同 → 不折腾
	if next.Version == cur.Version {
		res.Skipped = true
		return res, nil
	}

	// 4) 备份旧目录 → 就位新文件 → 再校验一次（这次校验的是真正生效的那份）
	backup := stage + "-old"
	if err := os.MkdirAll(backup, 0o755); err != nil {
		return res, fmt.Errorf("建备份目录失败：%w", err)
	}
	defer os.RemoveAll(backup)
	oldNames, err := moveRules(rulesDir, backup)
	if err != nil {
		return res, fmt.Errorf("备份旧规则失败：%w", err)
	}
	if err := copyInto(stage, rulesDir); err != nil {
		_ = restore(rulesDir, backup, oldNames)
		return res, fmt.Errorf("就位新规则失败，已回滚：%w", err)
	}
	if _, err := rules.LoadDir(rules.DefaultOptions(), rulesDir, []string{"*.yaml"}); err != nil {
		_ = restore(rulesDir, backup, oldNames)
		return res, fmt.Errorf("就位后校验未通过，已回滚：%w", err)
	}
	return res, nil
}

// moveRules 把 dir 下的规则文件移到 backup，返回被移动的文件名。
func moveRules(dir, backup string) ([]string, error) {
	names := []string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return names, err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		if err := os.Rename(filepath.Join(dir, e.Name()), filepath.Join(backup, e.Name())); err != nil {
			return names, err
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

func copyInto(from, to string) error {
	ents, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, e.Name()), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// restore 把备份里的旧文件放回去，并删掉这次新加进来的文件。
func restore(dir, backup string, oldNames []string) error {
	want := map[string]bool{}
	for _, n := range oldNames {
		want[n] = true
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		if !want[e.Name()] {
			_ = os.Remove(filepath.Join(dir, e.Name())) // 旧集合里没有的，就是这次新加的
		}
	}
	for _, n := range oldNames {
		data, err := os.ReadFile(filepath.Join(backup, n))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, n), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func get(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "donothack-rulesync")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s 返回 %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxFileBytes))
}

// apiBase 是 GitHub API 的基点。声明成变量是为了测试能指向本地假远端。
var apiBase = "https://api.github.com"

// LatestTag 取仓库里**最新的版本标签**。
//
// 为什么用 tags 而不是 releases/latest：只打 tag、不发 Release 是合法用法
// （例如只想让别人同步规则，不挂二进制包）。只看 Release 会把这种情况卡在
// "上一个已发布的版本"上 —— 用户以为同步到了最新规则，其实拿到的是旧的。
// tags 取不到（例如镜像只暴露 releases）时，再退回最新发布。
func LatestTag(ctx context.Context, hc *http.Client, contentsURL string) (string, error) {
	base := strings.TrimSpace(contentsURL)
	if base == "" {
		base = DefaultSource
	}
	i := strings.Index(base, "/repos/")
	if i < 0 {
		return "", fmt.Errorf("地址里没有 /repos/，无法推断仓库")
	}
	parts := strings.Split(base[i+len("/repos/"):], "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("地址里缺少 owner/repo")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	repoAPI := apiBase + "/repos/" + parts[0] + "/" + parts[1]

	if body, err := get(ctx, hc, repoAPI+"/tags?per_page=100"); err == nil {
		var tags []struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &tags); err == nil {
			best := ""
			for _, t := range tags {
				if newerTag(t.Name, best) {
					best = t.Name
				}
			}
			if best != "" {
				return best, nil
			}
		}
	}

	body, err := get(ctx, hc, repoAPI+"/releases/latest")
	if err != nil {
		return "", err
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", err
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return "", fmt.Errorf("最新发布里没有 tag_name")
	}
	return rel.TagName, nil
}

// newerTag 判断 a 是否比 b 新。只比数字段（`v1.3.0` 与 `1.2.0` 都认），
// 非数字后缀（`-rc1`）按同段处理 —— 用来挑"最新的版本标签"，不做严格 semver。
func newerTag(a, b string) bool {
	as, bs := tagParts(a), tagParts(b)
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y int
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func tagParts(s string) []int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	segs := strings.Split(s, ".")
	out := make([]int, 0, len(segs))
	for _, seg := range segs {
		n := 0
		for i := 0; i < len(seg) && seg[i] >= '0' && seg[i] <= '9'; i++ {
			n = n*10 + int(seg[i]-'0')
		}
		out = append(out, n)
	}
	return out
}

// LastResult 是最近一次同步的结果。
//
// 放在这个包里是因为它有两个读者：控制台的同步接口，和 /readyz ——
// 失败必须两边都看得见，否则运维会以为"点了没反应"，而线上还在用旧规则。
type LastResult struct {
	At          time.Time `json:"at"`
	OK          bool      `json:"ok"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	Skipped     bool      `json:"skipped"`
	Files       int       `json:"files"`
	Source      string    `json:"source"`
	Ref         string    `json:"ref"`
	Error       string    `json:"error,omitempty"`
}

var lastState struct {
	mu sync.Mutex
	r  *LastResult
}

// SetLast 记录一次同步结果（控制台/CLI 共用）。
func SetLast(r LastResult) {
	lastState.mu.Lock()
	lastState.r = &r
	lastState.mu.Unlock()
}

// Last 返回最近一次同步结果；从未同步过时返回 nil。
func Last() *LastResult {
	lastState.mu.Lock()
	defer lastState.mu.Unlock()
	return lastState.r
}

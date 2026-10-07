package server

import (
	"encoding/json"
	"strings"
	"testing"

	"donothack/internal/rulessync"
)

// /readyz 必须能看到最近一次规则同步的结果。
//
// 为什么钉这条：同步失败或没生效时，运维的第一反应是看 /readyz ——
// 如果那里什么都没有，"点了按钮没反应"和"同步成功了但规则没换"就分不出来。
// 运行时链路已在控制台侧验证（同步接口返回的 last 就是这份状态），
// 这里只钉住字段契约：名字是 rules_sync、且没同步过时不出现这个字段。
func TestReadyInfoCarriesRulesSync(t *testing.T) {
	rulessync.SetLast(rulessync.LastResult{
		OK: true, FromVersion: "sha256:aaaaaaaaaaaaaaaa", ToVersion: "sha256:bbbbbbbbbbbbbbbb",
		Files: 9, Source: "https://api.github.com/repos/guaidao2/donothack/contents/rules", Ref: "v1.2.0",
	})
	b, err := json.Marshal(ReadyInfo{RulesSync: rulessync.Last()})
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	out := string(b)
	if !strings.Contains(out, `"rules_sync"`) {
		t.Fatalf("/readyz 里没有 rules_sync 字段：%s", out)
	}
	if !strings.Contains(out, "sha256:bbbbbbbbbbbbbbbb") {
		t.Fatalf("同步后的指纹没进 /readyz：%s", out)
	}

	// 没同步过时不该出现这个字段（omitempty），免得界面把 nil 显示成"同步过了"
	empty, err := json.Marshal(ReadyInfo{})
	if err != nil {
		t.Fatalf("序列化失败：%v", err)
	}
	if strings.Contains(string(empty), "rules_sync") {
		t.Fatalf("未同步时不应出现 rules_sync：%s", string(empty))
	}
}

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"donothack/internal/profile"
)

// tmpPath 把测试用配置写在仓库内的 .tmp/test 下。
//
// 刻意不用 t.TempDir()：它落在系统临时目录，而本项目的纪律是
// "所有文件操作必须留在工作目录内"（见 AGENTS.md §1）。
func tmpPath(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join("..", "..", ".tmp", "test")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建测试目录失败：%v", err)
	}
	return filepath.Join(dir, name)
}

func writeConfig(t *testing.T, name, content string) string {
	t.Helper()
	p := tmpPath(t, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("写测试配置失败：%v", err)
	}
	return p
}

const minimalConfig = `
upstream:
  url: "http://127.0.0.1:9000"
`

func TestLoadMinimalConfigUsesDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, "minimal.yaml", minimalConfig))
	if err != nil {
		t.Fatalf("加载最小配置失败：%v", err)
	}
	if cfg.Engine.Mode != "detect" {
		t.Errorf("默认模式应为 detect，实际 %q", cfg.Engine.Mode)
	}
	if cfg.Engine.FailMode != "open" {
		t.Errorf("默认 fail_mode 应为 open，实际 %q", cfg.Engine.FailMode)
	}
	if cfg.Listen.HealthPath != "/healthz" || cfg.Listen.ReadyPath != "/readyz" {
		t.Errorf("健康探针路径默认值不对：%q / %q", cfg.Listen.HealthPath, cfg.Listen.ReadyPath)
	}
	if cfg.ResolvedProfile != profile.Medium {
		t.Errorf("默认档位应为 medium，实际 %q", cfg.ResolvedProfile)
	}
	if cfg.Listen.MaxConns != profile.Get(profile.Medium).MaxConns {
		t.Errorf("连接上限应取 medium 档值 %d，实际 %d",
			profile.Get(profile.Medium).MaxConns, cfg.Listen.MaxConns)
	}
}

// 档位必须真正生效：profile: small 不能继承 medium 的连接上限与检查体积。
func TestProfileDrivesLimits(t *testing.T) {
	cfg, err := Load(writeConfig(t, "small.yaml", "profile: small\n"+minimalConfig))
	if err != nil {
		t.Fatalf("加载 small 配置失败：%v", err)
	}
	small := profile.Get(profile.Small)
	if cfg.Listen.MaxConns != small.MaxConns {
		t.Errorf("max_conns = %d，期望 small 档的 %d", cfg.Listen.MaxConns, small.MaxConns)
	}
	if int64(cfg.Limits.MaxInspectBody) != small.MaxInspectBody {
		t.Errorf("max_inspect_body = %d，期望 %d", cfg.Limits.MaxInspectBody, small.MaxInspectBody)
	}
	if cfg.Limits.MaxRules != small.MaxRules {
		t.Errorf("max_rules = %d，期望 %d", cfg.Limits.MaxRules, small.MaxRules)
	}
	if cfg.Limits.RingBufferSize != small.RingBufferSize {
		t.Errorf("ring_buffer_size = %d，期望 %d", cfg.Limits.RingBufferSize, small.RingBufferSize)
	}
}

// 配置里显式写了的，以配置为准。
func TestExplicitLimitBeatsProfile(t *testing.T) {
	cfg, err := Load(writeConfig(t, "override.yaml", `
profile: small
limits:
  max_rules: 999
`+minimalConfig))
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	if cfg.Limits.MaxRules != 999 {
		t.Errorf("max_rules = %d，显式配置应覆盖档位值", cfg.Limits.MaxRules)
	}
}

// 未知字段必须报错：否则会出现"写了但没生效"这种最难查的故障。
func TestUnknownFieldRejected(t *testing.T) {
	_, err := Load(writeConfig(t, "unknown.yaml", minimalConfig+"\nunknown_thing: 1\n"))
	if err == nil {
		t.Fatal("未知字段应当被拒绝")
	}
	if !strings.Contains(err.Error(), "unknown_thing") {
		t.Errorf("错误信息应指出是哪个字段，实际：%v", err)
	}
}

func TestSizeParsing(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"512KiB", 512 << 10, false},
		{"1MiB", 1 << 20, false},
		{"1GiB", 1 << 30, false},
		{"64k", 64 << 10, false},
		{"1024", 1024, false},
		{"0", 0, false},
		{"abc", 0, true},
		{"-1MiB", 0, true},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseSize(%q) 应当报错", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseSize(%q) 意外报错：%v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseSize(%q) = %d，期望 %d", c.in, got, c.want)
		}
	}
}

func TestInvalidUpstreamRejected(t *testing.T) {
	cases := []string{
		"upstream:\n  url: \"ftp://127.0.0.1:9000\"\n",
		"upstream:\n  url: \"http://\"\n",
		"upstream:\n  url: \"\"\n",
	}
	for i, c := range cases {
		if _, err := Load(writeConfig(t, "bad_upstream_"+string(rune('a'+i))+".yaml", c)); err == nil {
			t.Errorf("第 %d 个非法上游配置应当被拒绝：%q", i, c)
		}
	}
}

func TestBadDurationRejected(t *testing.T) {
	_, err := Load(writeConfig(t, "bad_duration.yaml", minimalConfig+"\nlisten:\n  read_header_timeout: \"五秒\"\n"))
	if err == nil {
		t.Fatal("非法时长应当被拒绝")
	}
}

// MaxHeaderBytes 必须被压住：net/http 默认 1 MiB 在低配上是内存放大点。
func TestOversizedHeaderLimitRejected(t *testing.T) {
	_, err := Load(writeConfig(t, "big_header.yaml", minimalConfig+"\nlisten:\n  max_header_bytes: 2MiB\n"))
	if err == nil {
		t.Fatal("超过 1MiB 的 max_header_bytes 应当被拒绝")
	}
}

func TestInvalidEngineModeRejected(t *testing.T) {
	_, err := Load(writeConfig(t, "bad_mode.yaml", minimalConfig+"\nengine:\n  mode: monitor\n"))
	if err == nil {
		t.Fatal("非法 engine.mode 应当被拒绝")
	}
}

func TestTrustedProxiesParsing(t *testing.T) {
	cfg, err := Load(writeConfig(t, "proxies.yaml", minimalConfig+`
real_ip:
  trusted_proxies: ["10.0.0.0/8", "192.168.1.1", "2001:db8::/32"]
`))
	if err != nil {
		t.Fatalf("加载失败：%v", err)
	}
	got, err := cfg.TrustedProxies()
	if err != nil {
		t.Fatalf("解析可信代理失败：%v", err)
	}
	if len(got) != 3 {
		t.Fatalf("期望 3 条可信代理，实际 %d", len(got))
	}
	if _, err := Load(writeConfig(t, "bad_proxy.yaml", minimalConfig+`
real_ip:
  trusted_proxies: ["不是地址"]
`)); err == nil {
		t.Fatal("非法可信代理应当被拒绝")
	}
}

// 仓库里的示例配置必须始终能加载 —— 它是文档的一部分，坏了就是文档坏了。
func TestExampleConfigLoads(t *testing.T) {
	path := filepath.Join("..", "..", "config.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("示例配置不存在：%v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("示例配置无法加载：%v", err)
	}
	if cfg.ResolvedProfile == "" {
		t.Error("示例配置解析后档位为空")
	}
}

// Host 白名单：Host 头是攻击者可控的，应用若回显它就会出现"Host 头注入"类问题。
// 白名单是我们能主动收口的那一招。
func TestHostAllowed(t *testing.T) {
	cases := []struct {
		patterns []string
		host     string
		want     bool
	}{
		{nil, "anything.example", true},                               // 空白名单 = 不校验
		{[]string{"shop.example.com"}, "shop.example.com", true},      // 精确
		{[]string{"shop.example.com"}, "SHOP.example.com", true},      // 大小写不敏感
		{[]string{"shop.example.com"}, "shop.example.com:8443", true}, // 带端口
		{[]string{"shop.example.com"}, "evil.example", false},         // 不在名单
		{[]string{"*.example.com"}, "api.example.com", true},          // 子域通配
		{[]string{"*.example.com"}, "example.com", true},              // 裸域也认
		{[]string{"*.example.com"}, "example.com.evil.net", false},    // 后缀不能乱匹配
		{[]string{"[::1]"}, "[::1]", true},                            // IPv6 字面量
		{[]string{"10.0.0.1"}, "10.0.0.1:8080", true},
	}
	for _, c := range cases {
		u := UpstreamConfig{AllowedHosts: c.patterns}
		if got := u.HostAllowed(c.host); got != c.want {
			t.Errorf("HostAllowed(patterns=%v, host=%q)=%v，期望 %v", c.patterns, c.host, got, c.want)
		}
	}
}

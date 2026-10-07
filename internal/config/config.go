// Package config 负责加载、校验配置。
//
// 配置结构与  附录 B 一一对应：文档先改，代码后改。
// 未知字段一律报错（KnownFields），避免"写了但没生效"这种最难查的故障。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"donothack/internal/profile"
)

// Duration 让 YAML 里能写 "5s"、"30m"、"24h"。
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("第 %d 行：时长必须是字符串（如 5s）：%w", node.Line, err)
	}
	if strings.TrimSpace(s) == "" {
		*d = 0
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("第 %d 行：无法解析时长 %q：%w", node.Line, s, err)
	}
	*d = Duration(v)
	return nil
}

// D 返回标准库时长。
func (d Duration) D() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return time.Duration(d).String() }

// Size 让 YAML 里能写 "128KiB"、"512MiB"，也接受纯字节数。
type Size int64

func (s *Size) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		// 也接受纯整数
		var n int64
		if err2 := node.Decode(&n); err2 == nil {
			*s = Size(n)
			return nil
		}
		return fmt.Errorf("第 %d 行：体积必须是字符串（如 512KiB）或整数：%w", node.Line, err)
	}
	v, err := ParseSize(raw)
	if err != nil {
		return fmt.Errorf("第 %d 行：%w", node.Line, err)
	}
	*s = Size(v)
	return nil
}

// Bytes 返回字节数。
func (s Size) Bytes() int64 { return int64(s) }

// ParseSize 解析 "128KiB" / "512MiB" / "1GiB" / "1024" 形式的体积。
func ParseSize(s string) (int64, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, nil
	}
	upper := strings.ToUpper(t)
	mult := int64(1)
	for _, suf := range []struct {
		s string
		m int64
	}{
		{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30},
		{"B", 1},
	} {
		if strings.HasSuffix(upper, suf.s) {
			mult = suf.m
			t = t[:len(t)-len(suf.s)]
			break
		}
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
	if err != nil {
		return 0, fmt.Errorf("无法解析体积 %q（示例：512KiB、1MiB、1048576）", s)
	}
	if n < 0 {
		return 0, fmt.Errorf("体积不能为负：%q", s)
	}
	// **先算浮点再判范围**：`int64(n*mult)` 在溢出时的行为是平台相关的
	// （arm64 上会饱和到 MaxInt64，x86 上是未定义），于是"必须 > 0"之类的
	// 校验会被绕过，后续 make() 直接 panic。
	const maxSize = int64(1) << 50 // 1 PiB，远超任何合理配置
	v := n * float64(mult)
	if v > float64(maxSize) {
		return 0, fmt.Errorf("体积 %q 过大（上限 1PiB）—— 大概率是配置写错了", s)
	}
	return int64(v), nil
}

// BlockPageConfig 是拦截页配置。
//
// 拦截页有两个作用：告诉正常用户"为什么被拦、怎么申诉"，
// 以及（可选的）对外展示产品。**把展示做成开关**：开着等于告诉攻击者
// 这里有 WAF 且是哪一个，这个取舍交给部署方定。
type BlockPageConfig struct {
	// Status 是拦截状态码（默认 403）。限速与封禁固定用 429。
	Status int `yaml:"status"`
	// Branding 是否展示产品名与版本。
	Branding *bool `yaml:"branding"`
	// ProductName 展示的产品名。
	ProductName string `yaml:"product_name"`
	// ProductURL 产品主页（可空）。
	ProductURL string `yaml:"product_url"`
	// Contact 误报申诉渠道（可空）。
	Contact string `yaml:"contact"`
	// Title 页面标题。
	Title string `yaml:"title"`
	// File 是自定义模板文件路径（相对配置文件所在目录）。
	// 控制台保存自定义模板时也是写这个文件。
	File string `yaml:"file"`
}

// BrandingOn 返回是否展示品牌（默认开）。
func (c BlockPageConfig) BrandingOn() bool {
	if c.Branding == nil {
		return true
	}
	return *c.Branding
}

// Config 是完整配置。
type Config struct {
	Profile   string          `yaml:"profile"`
	Listen    ListenConfig    `yaml:"listen"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	TLS       TLSConfig       `yaml:"tls"`
	RealIP    RealIPConfig    `yaml:"real_ip"`
	Engine    EngineConfig    `yaml:"engine"`
	Rules     RulesConfig     `yaml:"rules"`
	Limits    LimitsConfig    `yaml:"limits"`
	RateLimit RateLimitConfig `yaml:"ratelimit"`
	Log       LogConfig       `yaml:"log"`
	Admin     AdminConfig     `yaml:"admin"`
	Alert     AlertConfig     `yaml:"alert"`
	BlockPage BlockPageConfig `yaml:"block_page"`

	// 以下三个字段由 Load 填充，不来自 YAML。
	// ResolvedProfile 是 profile: auto 解析后的实际档位。
	ResolvedProfile profile.Name      `yaml:"-"`
	ProfileSource   string            `yaml:"-"`
	Detection       profile.Detection `yaml:"-"`
	// Path 是配置文件的绝对路径。**用于解析配置里的相对路径**（自定义拦截页模板等）——
	// 相对路径必须相对配置文件，而不是相对进程工作目录，
	// 否则 systemd 与手动启动会读到不同的文件。
	Path string `yaml:"-"`
}

// ListenConfig 是数据面监听配置。
type ListenConfig struct {
	Addr              string   `yaml:"addr"`
	MaxHeaderBytes    Size     `yaml:"max_header_bytes"`
	ReadHeaderTimeout Duration `yaml:"read_header_timeout"`
	ReadTimeout       Duration `yaml:"read_timeout"`
	WriteTimeout      Duration `yaml:"write_timeout"`
	IdleTimeout       Duration `yaml:"idle_timeout"`
	ShutdownTimeout   Duration `yaml:"shutdown_timeout"`
	MaxConns          int      `yaml:"max_conns"`
	HTTP2             bool     `yaml:"http2"`
	HealthPath        string   `yaml:"health_path"`
	ReadyPath         string   `yaml:"ready_path"`
}

// UpstreamConfig 是上游配置（P0 只支持单上游）。
type UpstreamConfig struct {
	URL                   string   `yaml:"url"`
	DialTimeout           Duration `yaml:"dial_timeout"`
	ResponseHeaderTimeout Duration `yaml:"response_header_timeout"`
	IdleConnTimeout       Duration `yaml:"idle_conn_timeout"`
	MaxIdleConnsPerHost   int      `yaml:"max_idle_conns_per_host"`
	TCPNoDelay            bool     `yaml:"tcp_nodelay"`
	PreserveHost          bool     `yaml:"preserve_host"`
	// AllowedHosts 是允许的 Host 头白名单（支持 *.example.com 通配）。
	//
	// 空 = 不校验（默认，兼容任意域名）。
	// 非空时，Host 不在名单里的请求直接 400 —— 这是防 Host 头攻击
	// （密码重置投毒、缓存投毒、以及应用回显 Host 造成的注入类 finding）最直接的一招。
	// 只在**站点域名固定**时开启：多域名/多站点场景请留空。
	AllowedHosts []string `yaml:"allowed_hosts"`
}

// HostAllowed 判断 Host 是否在白名单内（空白名单视为允许一切）。
func (c UpstreamConfig) HostAllowed(host string) bool {
	if len(c.AllowedHosts) == 0 {
		return true
	}
	h := stripHostPort(host)
	for _, pat := range c.AllowedHosts {
		pat = strings.ToLower(strings.TrimSpace(pat))
		if pat == "" {
			continue
		}
		if strings.HasPrefix(pat, "*.") {
			// 通配：匹配子域（也匹配裸域，运维的直觉通常如此）
			suffix := pat[1:] // ".example.com"
			if strings.HasSuffix(h, suffix) || h == pat[2:] {
				return true
			}
			continue
		}
		// 名单条目也走同一套归一化（去端口、去 IPv6 方括号、转小写），
		// 否则 "[::1]" 这种写法永远匹配不上。
		if h == stripHostPort(pat) {
			return true
		}
	}
	return false
}

func stripHostPort(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return host
	}
	if strings.HasPrefix(host, "[") {
		if i := strings.Index(host, "]"); i > 0 {
			return host[1:i]
		}
	}
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i+1:], ":") {
		if _, err := strconv.Atoi(host[i+1:]); err == nil {
			return host[:i]
		}
	}
	return host
}

// TLSConfig 是数据面 TLS 配置（默认关，很多站点跑明文 HTTP）。
type TLSConfig struct {
	Enabled    bool   `yaml:"enabled"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	MinVersion string `yaml:"min_version"`
}

// RealIPConfig 控制真实客户端 IP 还原。
type RealIPConfig struct {
	TrustedProxies []string `yaml:"trusted_proxies"`
	Header         string   `yaml:"header"`
}

// EngineConfig 是检测引擎配置（P0 只读取并暴露，不参与决策）。
type EngineConfig struct {
	Mode                    string `yaml:"mode"`
	FailMode                string `yaml:"fail_mode"`
	Degrade                 string `yaml:"degrade"`
	InboundAnomalyThreshold int    `yaml:"inbound_anomaly_threshold"`
	// CategoryThresholds 只在 `mode: mixed` 下生效：类目 → 该类的拦截阈值。
	//
	// 为什么要显式加这个字段：代码里 `Engine.CategoryThresholds`
	// 一直存在、mixed 的判定也一直"看类目阈值"，但**从来没有数据源** ——
	// 于是 mixed 静默等价于 block，与  "mixed 看类目阈值" 相反。
	//
	// 语义：某类目的累计分数达到它自己的阈值就拦；没配的类目回落到
	// `inbound_anomaly_threshold`。多个类目同时命中时取**最小**的那个阈值。
	CategoryThresholds map[string]int `yaml:"category_thresholds"`
	// BanOnBlock 表示检测判定拦截时同时临时封禁来源 IP。
	// 默认关：封禁是"加码"动作，误判时影响面比单次拦截大得多，
	// 应当等规则稳定、观察过误报之后再开。
	BanOnBlock bool `yaml:"ban_on_block"`
	// BlockBanDuration 是上面那个封禁的时长。
	BlockBanDuration Duration `yaml:"block_ban_duration"`
}

// RulesConfig 是规则集配置。
type RulesConfig struct {
	Dir            string   `yaml:"dir"`
	Files          []string `yaml:"files"`
	ReloadInterval Duration `yaml:"reload_interval"`
	SelfTest       bool     `yaml:"self_test"`
}

// LimitsConfig 是各项资源上限。每个字段都必须有界，见 。
type LimitsConfig struct {
	MaxInspectBody         Size `yaml:"max_inspect_body"`
	MaxURILength           int  `yaml:"max_uri_length"`
	MaxHeaders             int  `yaml:"max_headers"`
	MaxParams              int  `yaml:"max_params"`
	MaxParamValueLen       Size `yaml:"max_param_value_len"`
	MaxJSONDepth           int  `yaml:"max_json_depth"`
	MaxJSONNodes           int  `yaml:"max_json_nodes"`
	MaxTransformDepth      int  `yaml:"max_transform_depth"`
	MaxPrefilterLiterals   int  `yaml:"max_prefilter_literals"`
	MaxRules               int  `yaml:"max_rules"`
	RateLimitTableCapacity int  `yaml:"ratelimit_table_capacity"`
	RingBufferSize         int  `yaml:"ring_buffer_size"`
}

// RateLimitConfig 是限速与封禁配置。
type RateLimitConfig struct {
	Enabled bool `yaml:"enabled"`
	// MaxKeys 覆盖档位默认的状态表容量（0 = 用档位值）。
	MaxKeys      int      `yaml:"max_keys"`
	DefaultRPS   int      `yaml:"default_rps"`
	DefaultBurst int      `yaml:"default_burst"`
	BanAfterHits int      `yaml:"ban_after_hits"`
	BanWindow    Duration `yaml:"ban_window"`
	BanDuration  Duration `yaml:"ban_duration"`
	Whitelist    []string `yaml:"whitelist"`
}

// LogConfig 是日志配置。
//
// 应用日志与访问/审计日志分开：前者默认到 stderr，后者默认到 stdout。
// 混在一个文件里会让"按字段过滤审计记录"变得别扭。
//
// 轮转相关的字段不是"锦上添花"：压测实测 29k rps 全量记录约 22 MB/s，
// 没有这几道上限，一台 20GB 磁盘的 VPS 十几分钟就会被日志写满，
// 而写满之后是"WAF 静默失能"。
type LogConfig struct {
	Level     string `yaml:"level"`
	Format    string `yaml:"format"`     // json | text
	Output    string `yaml:"output"`     // 访问/审计日志：stdout | file
	File      string `yaml:"file"`       // output=file 时的路径
	AppOutput string `yaml:"app_output"` // 应用日志：stderr | stdout | file（空 = stderr）
	AppFile   string `yaml:"app_file"`   // app_output=file 时的路径

	// 轮转与保留。三道上限各管一件事，缺一不可。
	MaxSizeMB  int  `yaml:"max_size_mb"`  // 单文件多大就轮转
	MaxBackups int  `yaml:"max_backups"`  // 最多留几份轮转文件
	TotalMaxMB int  `yaml:"total_max_mb"` // 日志目录总配额，超了删最旧的（0 = 不限）
	MinFreeMB  int  `yaml:"min_free_mb"`  // 磁盘剩余低于此值就丢弃日志（0 = 不检查）
	Compress   bool `yaml:"compress"`     // 轮转后 gzip 旧文件

	// 访问日志策略：all 全记 | hit 只记非 pass | sample 非 pass 全记 + pass 按比例采样
	AccessMode        string `yaml:"access_mode"`
	AccessSampleRatio int    `yaml:"access_sample_ratio"` // sample 模式下每 N 条记 1 条

	CapturePayload bool `yaml:"capture_payload"`
}

// ConsoleTLSConfig 是控制台监听自身的 TLS。
type ConsoleTLSConfig struct {
	Enabled        bool   `yaml:"enabled"`
	CertFile       string `yaml:"cert_file"`
	KeyFile        string `yaml:"key_file"`
	AutoSelfSigned bool   `yaml:"auto_self_signed"`
}

// EventsConfig 是事件存储与查询上限。
type EventsConfig struct {
	RetentionDays  int      `yaml:"retention_days"`
	RetentionBytes Size     `yaml:"retention_bytes"`
	MaxQueryRange  Duration `yaml:"max_query_range"`
	MaxRows        int      `yaml:"max_rows"`
	QueryTimeout   Duration `yaml:"query_timeout"`
	SQLite         bool     `yaml:"sqlite"`
}

// AdminConfig 是控制台与控制面 API 配置。
type AdminConfig struct {
	Enabled bool             `yaml:"enabled"`
	Addr    string           `yaml:"addr"`
	TLS     ConsoleTLSConfig `yaml:"tls"`
	// AuthMode 目前只实现了 `session`。
	//
	// `session+basic`（再叠一层 Basic 给 CLI 用）**已不再需要** ——
	// CLI 走 `admin.api_token`，它比 Basic 更适合脚本：不进浏览器凭据弹窗、
	// 可单独轮换、可单独关闭。为了让"配了但没生效"这种事不再发生，
	// `session+basic` 会在加载期被**拒绝**并提示改用 api_token。
	AuthMode     string `yaml:"auth_mode"` // 只接受 session
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
	APIToken     string `yaml:"api_token"`
	TOTPEnabled  bool   `yaml:"totp_enabled"`
	// TOTPSecret 是 base32 密钥。**必须由运维自己保存**：只写在配置里，
	// 服务端不生成、不落盘到别处 —— 换机器/重启后仍然能对上。
	TOTPSecret         string       `yaml:"totp_secret"`
	AllowIPs           []string     `yaml:"allow_ips"`
	AllowInsecure      bool         `yaml:"allow_insecure"`
	SessionIdleTimeout Duration     `yaml:"session_idle_timeout"`
	MaxLoginFails      int          `yaml:"max_login_fails"`
	Lockout            Duration     `yaml:"lockout"`
	Pprof              bool         `yaml:"pprof"`
	Events             EventsConfig `yaml:"events"`
}

// AlertConfig 是告警钩子配置（P4 实现）。
type AlertConfig struct {
	Enabled bool   `yaml:"enabled"`
	Webhook string `yaml:"webhook"`
	// AllowPrivateHosts 允许 webhook 指向私有/回环地址。
	//
	// **默认 false**（见 internal/notify/egress.go）：webhook 地址是控制台可改的，
	// 放开就等于给了"从 WAF 机器发起内网请求"的能力（内网探测、云元数据 169.254.169.254）。
	// 自建告警网关在内网时再显式打开。
	AllowPrivateHosts bool `yaml:"allow_private_hosts"`
	// MinSeverity 是发送门槛（info/low/medium/high/critical），留空=不过滤。
	MinSeverity string `yaml:"min_severity"`
	// Cooldown 是同类告警的最小发送间隔（负值=关闭冷却）。
	Cooldown Duration `yaml:"cooldown"`
	// QueueCap 是有界队列容量（满了丢事件并计数，绝不阻塞数据面）。
	QueueCap int `yaml:"queue_cap"`
}

// Default 返回 medium 档的默认配置，对应  附录 B。
func Default() *Config {
	return &Config{
		Profile: string(profile.Medium),
		Listen: ListenConfig{
			Addr:              "0.0.0.0:8080",
			MaxHeaderBytes:    Size(32 << 10),
			ReadHeaderTimeout: Duration(5 * time.Second),
			ReadTimeout:       Duration(15 * time.Second),
			WriteTimeout:      Duration(30 * time.Second),
			IdleTimeout:       Duration(60 * time.Second),
			ShutdownTimeout:   Duration(15 * time.Second),
			// MaxConns 由 ApplyProfile 按档位填充：档位是唯一的上限来源，
			// 否则 profile: small 会拿到 medium 的连接上限。
			HTTP2:      false,
			HealthPath: "/healthz",
			ReadyPath:  "/readyz",
		},
		Upstream: UpstreamConfig{
			URL:                   "http://127.0.0.1:9000",
			DialTimeout:           Duration(5 * time.Second),
			ResponseHeaderTimeout: Duration(30 * time.Second),
			IdleConnTimeout:       Duration(30 * time.Second),
			TCPNoDelay:            true,
			PreserveHost:          false,
		},
		TLS: TLSConfig{Enabled: false, MinVersion: "1.2"},
		RealIP: RealIPConfig{
			TrustedProxies: nil,
			Header:         "X-Forwarded-For",
		},
		Engine: EngineConfig{
			Mode:                    "detect",
			FailMode:                "open",
			Degrade:                 "auto",
			InboundAnomalyThreshold: 5,
		},
		Rules: RulesConfig{
			Dir:            "./rules",
			Files:          []string{"*.yaml"},
			ReloadInterval: 0,
			SelfTest:       true,
		},
		Limits: LimitsConfig{
			// 与档位相关的上限由 ApplyProfile 填充；其余是全局默认值。
			MaxURILength:      8192,
			MaxHeaders:        100,
			MaxParams:         1000,
			MaxParamValueLen:  Size(64 << 10),
			MaxJSONDepth:      32,
			MaxJSONNodes:      10000,
			MaxTransformDepth: 8,
		},
		RateLimit: RateLimitConfig{
			Enabled:      true,
			DefaultRPS:   100,
			DefaultBurst: 200,
			BanAfterHits: 20,
			BanWindow:    Duration(60 * time.Second),
			BanDuration:  Duration(300 * time.Second),
		},
		Log: LogConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
			File:   "./logs/donothack.jsonl",
			// 单文件 100 MiB；总配额 512 MiB —— 注意总配额是硬顶，
			// 所以实际保留份数通常少于 max_backups（这里 10 × 100MiB 会被总配额先削到约 5 份）。
			MaxSizeMB:  100,
			MaxBackups: 10,
			TotalMaxMB: 512,
			// 磁盘剩余低于 1 GiB 就停止写日志：日志的价值远低于业务可用性。
			MinFreeMB: 1024,
			Compress:  true,
			// 默认全记：P0/P1 还没有检测能力，此时只记"非 pass"等于什么都不记。
			// **上到 block 模式时应改成 hit 或 sample** —— 审计日志要留的是
			// "被拦了什么"，不是"有多少正常请求通过"。
			AccessMode:        "all",
			AccessSampleRatio: 100,
		},
		Admin: AdminConfig{
			Enabled:            true,
			Addr:               "127.0.0.1:9443",
			AuthMode:           "session",
			Username:           "admin",
			TLS:                ConsoleTLSConfig{Enabled: true, AutoSelfSigned: true},
			SessionIdleTimeout: Duration(30 * time.Minute),
			MaxLoginFails:      5,
			Lockout:            Duration(15 * time.Minute),
			Events: EventsConfig{
				RetentionDays:  7,
				RetentionBytes: Size(512 << 20),
				MaxQueryRange:  Duration(24 * time.Hour),
				MaxRows:        200,
				QueryTimeout:   Duration(3 * time.Second),
			},
		},
		Alert: AlertConfig{Enabled: false},
	}
}

// ApplyProfile 用档位参数填充所有"与档位相关"的上限。
//
// 规则：**配置里显式写了就以配置为准，没写就用档位值。**
// 这样 profile: small 不会意外继承 medium 的连接上限与检查体积。
func (c *Config) ApplyProfile(p profile.Params) {
	if c.Listen.MaxConns == 0 {
		c.Listen.MaxConns = p.MaxConns
	}
	if c.Upstream.MaxIdleConnsPerHost == 0 {
		c.Upstream.MaxIdleConnsPerHost = p.MaxIdleConnsPerHost
	}
	if c.Limits.MaxInspectBody == 0 {
		c.Limits.MaxInspectBody = Size(p.MaxInspectBody)
	}
	if c.Limits.MaxPrefilterLiterals == 0 {
		c.Limits.MaxPrefilterLiterals = p.MaxPrefilterLiterals
	}
	if c.Limits.MaxRules == 0 {
		c.Limits.MaxRules = p.MaxRules
	}
	if c.Limits.RateLimitTableCapacity == 0 {
		c.Limits.RateLimitTableCapacity = p.RateLimitTableCapacity
	}
	if c.Limits.RingBufferSize == 0 {
		c.Limits.RingBufferSize = p.RingBufferSize
	}
}

// removedFieldHint 把"已移除的配置段"翻译成一句能照做的提示。
//
// 为什么值得单独写：严格解码（KnownFields）遇到旧配置只会回
// `field gate not found in type config.AdminConfig` —— 运维看不懂，
// 而他要做的动作其实很简单：把 admin.gate 整段删掉。
func removedFieldHint(raw []byte) string {
	var probe struct {
		Admin map[string]any `yaml:"admin"`
	}
	if err := yaml.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	if _, ok := probe.Admin["gate"]; !ok {
		return ""
	}
	return "admin.gate（HTTP Basic 门槛）已移除：认证只由表单登录 + 会话承担。\n" +
		"  请把 admin 段落里的整个 gate: 块删掉（连同它下面缩进的所有行），然后重启。\n" +
		"  想限制来源请用 admin.allow_ips；想细分登录爆破阈值用 admin.max_login_fails / admin.lockout。"
}

// Load 读取并校验配置文件。默认值先铺好，YAML 里出现的字段覆盖之；
// 档位相关的上限在档位解析完成后再填充。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置失败：%w", err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("配置文件 %s 是空的", path)
		}
		// 老配置里残留的门槛字段给一句人话，别丢原始 yaml 报错给运维。
		if removed := removedFieldHint(raw); removed != "" {
			return nil, fmt.Errorf("解析 %s 失败：%s", path, removed)
		}
		return nil, fmt.Errorf("解析 %s 失败：%w", path, err)
	}

	// 记下配置文件绝对路径：配置里的相对路径（自定义拦截页模板等）
	// 一律相对配置文件，而不是相对进程工作目录。
	if abs, err := filepath.Abs(path); err == nil {
		cfg.Path = abs
	} else {
		cfg.Path = path
	}

	pn, err := profile.Parse(cfg.Profile)
	if err != nil {
		return nil, fmt.Errorf("%s：%w", path, err)
	}
	det := profile.Detect()
	resolved, source := det.Resolve(pn)
	cfg.ResolvedProfile = resolved
	cfg.ProfileSource = source
	cfg.Detection = det
	cfg.ApplyProfile(profile.Get(resolved))

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s 校验失败：%w", path, err)
	}
	return cfg, nil
}

// Validate 校验配置。宁可启动失败，也不要带着错配置跑起来。
func (c *Config) Validate() error {
	if _, err := profile.Parse(c.Profile); err != nil {
		return err
	}
	// 健康/就绪路径会被注册到 ServeMux，而 `/` 与其它模式冲突会在**注册期 panic** ——
	// 那意味着配置写错时进程直接崩，而不是给出一句人话。
	for _, hp := range []struct {
		name, val string
	}{
		{"listen.health_path", c.Listen.HealthPath},
		{"listen.ready_path", c.Listen.ReadyPath},
	} {
		v := strings.TrimSpace(hp.val)
		if v == "" {
			continue
		}
		if !strings.HasPrefix(v, "/") {
			return fmt.Errorf("%s 必须以 / 开头，实际 %q", hp.name, v)
		}
		if v == "/" {
			return fmt.Errorf("%s 不能是 /（会和其它路由冲突并在注册期 panic）；建议用 /healthz", hp.name)
		}
	}
	if strings.TrimSpace(c.Listen.HealthPath) != "" &&
		strings.TrimSpace(c.Listen.HealthPath) == strings.TrimSpace(c.Listen.ReadyPath) {
		return fmt.Errorf("listen.health_path 与 listen.ready_path 不能相同（都是 %q）", c.Listen.HealthPath)
	}

	if _, err := c.ListenAddr(); err != nil {
		return err
	}
	if err := c.validateListen(); err != nil {
		return err
	}
	if err := c.validateUpstream(); err != nil {
		return err
	}
	// 可信代理必须在加载期就校验：等到运行期才发现写错了，
	// 那时限速与封禁已经在用错误的客户端 IP 了。
	if _, err := c.TrustedProxies(); err != nil {
		return err
	}
	if err := c.validateEngine(); err != nil {
		return err
	}
	if err := c.validateLimits(); err != nil {
		return err
	}
	if err := c.validateAdmin(); err != nil {
		return err
	}
	return c.validateLog()
}

// validateAdmin 校验控制台配置。
//
// 目的很具体：**让"配了但没生效"变成启动期的错误**，而不是线上静默降级。
// 这几条都是审计里发现的"死配置"（01-F-02 / 01-F-05）：
// 配置项写在那里、文档也讲了，但代码从来不读 —— 运维以为自己加固过了。
func (c *Config) validateAdmin() error {
	a := c.Admin
	if !a.Enabled {
		return nil
	}

	switch strings.TrimSpace(a.AuthMode) {
	case "", "session":
		// 唯一实现的取值
	case "session+basic":
		return fmt.Errorf("admin.auth_mode: session+basic 已不再实现（CLI 请改用 admin.api_token）—— " +
			"它原先只是被忽略，会让人以为多了一层 Basic")
	default:
		return fmt.Errorf("admin.auth_mode 只支持 session，实际 %q", a.AuthMode)
	}

	if a.MaxLoginFails < 0 {
		return fmt.Errorf("admin.max_login_fails 不能为负（0 表示用默认值 5），实际 %d", a.MaxLoginFails)
	}

	// TOTP 开关与密钥必须成对：只开开关不给密钥的话，每个实例重启后都会
	// 拿着一把自己生成的密钥，运维认证器里那把立刻变成废码。
	if a.TOTPEnabled && strings.TrimSpace(a.TOTPSecret) == "" {
		return fmt.Errorf("admin.totp_enabled 为 true 但没有 admin.totp_secret：" +
			"服务端不会替你生成（生成一次你就再也对不上了）")
	}
	return nil
}

func (c *Config) validateListen() error {
	l := c.Listen
	if l.MaxHeaderBytes <= 0 {
		return fmt.Errorf("listen.max_header_bytes 必须为正数（默认 32KiB；net/http 默认 1MiB 在低配下是内存放大点）")
	}
	if l.MaxHeaderBytes > 1<<20 {
		return fmt.Errorf("listen.max_header_bytes = %d 过大，超过 net/http 默认值 1MiB", l.MaxHeaderBytes)
	}
	if l.ReadHeaderTimeout <= 0 {
		return fmt.Errorf("listen.read_header_timeout 必须为正数（防 slowloris）")
	}
	if l.MaxConns <= 0 {
		return fmt.Errorf("listen.max_conns 必须为正数（并发连接上限，无界即漏洞）")
	}
	if l.ShutdownTimeout <= 0 {
		return fmt.Errorf("listen.shutdown_timeout 必须为正数")
	}
	for _, p := range []struct{ name, val string }{
		{"listen.health_path", l.HealthPath},
		{"listen.ready_path", l.ReadyPath},
	} {
		if !strings.HasPrefix(p.val, "/") {
			return fmt.Errorf("%s 必须以 / 开头，当前为 %q", p.name, p.val)
		}
	}
	if l.HealthPath == l.ReadyPath {
		return fmt.Errorf("listen.health_path 与 listen.ready_path 不能相同")
	}
	return nil
}

func (c *Config) validateUpstream() error {
	if strings.TrimSpace(c.Upstream.URL) == "" {
		return fmt.Errorf("upstream.url 必填")
	}
	u, err := url.Parse(c.Upstream.URL)
	if err != nil {
		return fmt.Errorf("upstream.url 无法解析：%w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("upstream.url 的 scheme 必须是 http 或 https，当前为 %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("upstream.url 缺少主机名：%q", c.Upstream.URL)
	}
	if c.Upstream.DialTimeout <= 0 {
		return fmt.Errorf("upstream.dial_timeout 必须为正数")
	}
	if c.Upstream.ResponseHeaderTimeout <= 0 {
		return fmt.Errorf("upstream.response_header_timeout 必须为正数")
	}
	if c.Upstream.MaxIdleConnsPerHost <= 0 {
		return fmt.Errorf("upstream.max_idle_conns_per_host 必须为正数")
	}
	return nil
}

func (c *Config) validateEngine() error {
	switch c.Engine.Mode {
	case "detect", "block", "mixed":
	default:
		return fmt.Errorf("engine.mode 必须是 detect | block | mixed，当前为 %q", c.Engine.Mode)
	}
	switch c.Engine.FailMode {
	case "open", "closed":
	default:
		return fmt.Errorf("engine.fail_mode 必须是 open | closed，当前为 %q", c.Engine.FailMode)
	}
	switch c.Engine.Degrade {
	case "auto", "off":
	default:
		return fmt.Errorf("engine.degrade 必须是 auto | off，当前为 %q", c.Engine.Degrade)
	}
	if c.Engine.InboundAnomalyThreshold <= 0 {
		return fmt.Errorf("engine.inbound_anomaly_threshold 必须为正数")
	}
	// 类目阈值只对 mixed 有意义。**配了但模式不对要说出来**，
	// 否则运维会以为"我配了类目阈值"，而实际走的是 block 的单阈值（04-F4）。
	for cat, th := range c.Engine.CategoryThresholds {
		if th < 1 {
			return fmt.Errorf("engine.category_thresholds[%s] 必须为正数（实际 %d）", cat, th)
		}
	}
	if len(c.Engine.CategoryThresholds) > 0 && c.Engine.Mode != "mixed" {
		return fmt.Errorf("engine.category_thresholds 只在 mode: mixed 下生效，当前 mode 是 %q；"+
			"要么把模式改成 mixed，要么删掉类目阈值", c.Engine.Mode)
	}
	if c.Engine.Mode == "mixed" && len(c.Engine.CategoryThresholds) == 0 {
		return fmt.Errorf("engine.mode 是 mixed 但没有配 engine.category_thresholds：" +
			"那样它和 block 完全一样，配 mixed 就没意义了")
	}
	return nil
}

func (c *Config) validateLimits() error {
	l := c.Limits
	if l.MaxInspectBody <= 0 {
		return fmt.Errorf("limits.max_inspect_body 必须为正数（可为 0 关闭请求体检查，但不能为负）")
	}
	if l.MaxRules <= 0 {
		return fmt.Errorf("limits.max_rules 必须为正数（规则集条数上限，无界即漏洞）")
	}
	if l.RateLimitTableCapacity <= 0 {
		return fmt.Errorf("limits.ratelimit_table_capacity 必须为正数（否则伪造源 IP 喷洒可打爆内存）")
	}
	if l.RingBufferSize <= 0 {
		return fmt.Errorf("limits.ring_buffer_size 必须为正数")
	}
	if l.MaxJSONDepth <= 0 || l.MaxJSONNodes <= 0 {
		return fmt.Errorf("limits.max_json_depth / max_json_nodes 必须为正数")
	}
	if l.MaxTransformDepth <= 0 {
		return fmt.Errorf("limits.max_transform_depth 必须为正数")
	}
	if l.MaxURILength <= 0 || l.MaxHeaders <= 0 || l.MaxParams <= 0 || l.MaxParamValueLen <= 0 {
		return fmt.Errorf("limits 里的长度类上限必须为正数")
	}
	return nil
}

func (c *Config) validateLog() error {
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level 必须是 debug | info | warn | error，当前为 %q", c.Log.Level)
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		return fmt.Errorf("log.format 必须是 json | text，当前为 %q", c.Log.Format)
	}
	switch c.Log.Output {
	case "stdout", "":
	case "file":
		if strings.TrimSpace(c.Log.File) == "" {
			return fmt.Errorf("log.output=file 时 log.file 必填")
		}
	default:
		return fmt.Errorf("log.output 必须是 stdout | file，当前为 %q", c.Log.Output)
	}
	switch c.Log.AppOutput {
	case "", "stderr", "stdout":
	case "file":
		if strings.TrimSpace(c.Log.AppFile) == "" {
			return fmt.Errorf("log.app_output=file 时 log.app_file 必填")
		}
	default:
		return fmt.Errorf("log.app_output 必须是 stderr | stdout | file，当前为 %q", c.Log.AppOutput)
	}

	// 轮转与保留：这几项是"日志不会把磁盘写满"的全部保障，必须校验。
	if c.Log.MaxSizeMB <= 0 {
		return fmt.Errorf("log.max_size_mb 必须为正数（单文件上限；无上限即等于把磁盘交给日志）")
	}
	if c.Log.MaxBackups < 0 {
		return fmt.Errorf("log.max_backups 不能为负（0 表示只保留当前文件）")
	}
	if c.Log.TotalMaxMB < 0 {
		return fmt.Errorf("log.total_max_mb 不能为负（0 表示不限总配额）")
	}
	if c.Log.MinFreeMB < 0 {
		return fmt.Errorf("log.min_free_mb 不能为负（0 表示不检查磁盘水位）")
	}
	if c.Log.TotalMaxMB > 0 && c.Log.TotalMaxMB < c.Log.MaxSizeMB {
		return fmt.Errorf("log.total_max_mb(%d) 小于 log.max_size_mb(%d)：总配额连一个文件都放不下，会不停删刚写完的文件",
			c.Log.TotalMaxMB, c.Log.MaxSizeMB)
	}
	switch c.Log.AccessMode {
	case "", "all", "hit", "sample":
	default:
		return fmt.Errorf("log.access_mode 必须是 all | hit | sample，当前为 %q", c.Log.AccessMode)
	}
	if c.Log.AccessSampleRatio < 0 {
		return fmt.Errorf("log.access_sample_ratio 不能为负")
	}
	return nil
}

// ListenAddr 解析并返回监听地址。
func (c *Config) ListenAddr() (string, error) {
	host, port, err := net.SplitHostPort(c.Listen.Addr)
	if err != nil {
		return "", fmt.Errorf("listen.addr 必须是 host:port 形式，当前为 %q：%w", c.Listen.Addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("listen.addr 缺少端口：%q", c.Listen.Addr)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("listen.addr 端口不是数字：%q", port)
	}
	return net.JoinHostPort(host, port), nil
}

// UpstreamURL 返回解析后的上游地址。
func (c *Config) UpstreamURL() (*url.URL, error) { return url.Parse(c.Upstream.URL) }

// ProfileName 返回规范化后的档位名（可能是 auto）。
func (c *Config) ProfileName() (profile.Name, error) { return profile.Parse(c.Profile) }

// TrustedProxies 解析可信代理 CIDR 列表。
func (c *Config) TrustedProxies() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.RealIP.TrustedProxies))
	for _, s := range c.RealIP.TrustedProxies {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		return nil, fmt.Errorf("real_ip.trusted_proxies 里的 %q 既不是 CIDR 也不是 IP", s)
	}
	return out, nil
}

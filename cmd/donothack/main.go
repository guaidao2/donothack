// Command donothack 是 WAF 的唯一二进制。
//
// 子命令：
//
//	donothack -c config.yaml              启动数据面（默认行为）
//	donothack rules check -d ./rules      只校验规则集，不起服务
//	donothack rules test  -d ./rules      跑规则自带的正负样本
//	donothack test -r req.http            拿一条真实原始请求离线跑规则，看命中链路
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"donothack/internal/audit"
	"donothack/internal/blockpage"
	"donothack/internal/config"
	"donothack/internal/console"
	"donothack/internal/control"
	"donothack/internal/degrade"
	"donothack/internal/engine"
	"donothack/internal/eventstore"
	"donothack/internal/notify"
	"donothack/internal/parser"
	"donothack/internal/pipeline"
	"donothack/internal/profile"
	"donothack/internal/proxy"
	"donothack/internal/ratelimit"
	"donothack/internal/realip"
	"donothack/internal/rules"
	"donothack/internal/server"
	"donothack/internal/tx"
	"donothack/internal/version"
)

// redactWebhookHost 只留下 webhook 的主机名（去掉路径与 query）。
//
// 钉钉/飞书/Slack 的 webhook 都是 `https://host/path/<机器人 token>` 的形态，
// 而 token 就在路径里 —— 所以**路径一个字都不能进日志**（
// 原先 main.go 直接把整个 URL 打进应用日志）。
func redactWebhookHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "(无法解析)"
	}
	return u.Scheme + "://" + u.Host + "/…（路径已脱敏）"
}

func main() {
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "rules":
			os.Exit(runRulesCmd(args[1:]))
		case "test":
			os.Exit(runTestCmd(args[1:]))
		case "version":
			fmt.Println(version.Full())
			return
		case "hash-password":
			os.Exit(runHashPasswordCmd(args[1:]))
		case "help", "-h", "--help":
			usage()
			return
		default:
			fmt.Fprintf(os.Stderr, "donothack: 未知子命令 %q\n\n", args[0])
			usage()
			os.Exit(2)
		}
	}

	var (
		cfgPath    = flag.String("c", "config.yaml", "配置文件路径")
		showVer    = flag.Bool("version", false, "打印版本后退出")
		checkCfg   = flag.Bool("check-config", false, "只校验配置后退出")
		showBudget = flag.Bool("print-budget", false, "打印档位与内存预算表后退出")
		noRules    = flag.Bool("no-rules", false, "不加载规则集，只做纯转发（调试用）")
	)
	// -h / --help 交给同一个 usage：flag 包默认会打印 "Usage of <本机绝对路径>"，
	// 既不列子命令，又把本机路径泄在帮助里。
	flag.Usage = usage
	flag.Parse()

	if *showVer {
		fmt.Println(version.Info())
		return
	}
	if err := run(*cfgPath, *checkCfg, *showBudget, *noRules); err != nil {
		fmt.Fprintf(os.Stderr, "donothack: %v\n", err)
		os.Exit(1)
	}
}

func usage() { writeUsage(os.Stderr) }

// writeUsage 把帮助文本写进 w。
//
// 拆出 writer 参数是为了能被测试断言"帮助里必须列出全部子命令与参数"：
// 帮助缺项是常有的事（加了子命令忘了写帮助，用户就只能靠翻源码），
// 靠人肉记容易漏，所以交给门禁守。
func writeUsage(w io.Writer) {
	fmt.Fprint(w, `donothack —— 请求侧 Web 应用防火墙

用法：
  donothack -c config.yaml              启动数据面
  donothack rules check -d ./rules      校验规则集
  donothack rules test  -d ./rules      跑规则自带的正负样本
  donothack test -r req.http            离线跑一条原始请求
  donothack hash-password               生成控制台口令哈希（写进 admin.password_hash）
  donothack version                     打印版本
  donothack help                        显示本帮助

参数（不带子命令时）：
  -c string        配置文件路径（默认 "config.yaml"）
  -version         打印版本后退出
  -check-config    只校验配置后退出
  -print-budget    打印档位与内存预算表后退出
  -no-rules        不加载规则集，只做纯转发（调试用）
  -h, --help       显示本帮助

完整说明见 README.md。
`)
}

// ---------------------------------------------------------------- 起服务

func run(cfgPath string, checkOnly, printBudget, noRules bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	p := profile.Get(cfg.ResolvedProfile)
	det := cfg.Detection
	memLimit := profile.Apply(p, det.MemBytes)
	budget := profile.ComputeBudget(p, det.MemBytes, det.MemSource)

	if checkOnly {
		fmt.Printf("配置校验通过：%s\n", cfgPath)
		fmt.Printf("  档位：%s（%s）\n", cfg.ResolvedProfile, cfg.ProfileSource)
		fmt.Printf("  监听：%s\n", cfg.Listen.Addr)
		fmt.Printf("  上游：%s\n", cfg.Upstream.URL)
		fmt.Printf("  模式：%s（fail_mode=%s，degrade=%s）\n",
			cfg.Engine.Mode, cfg.Engine.FailMode, cfg.Engine.Degrade)
		return nil
	}
	if err := budget.Check(); err != nil {
		return err
	}

	logger, err := audit.New(audit.Options{
		Level:             cfg.Log.Level,
		Format:            cfg.Log.Format,
		Output:            cfg.Log.Output,
		File:              cfg.Log.File,
		AppOutput:         cfg.Log.AppOutput,
		AppFile:           cfg.Log.AppFile,
		MaxSizeMB:         cfg.Log.MaxSizeMB,
		MaxBackups:        cfg.Log.MaxBackups,
		TotalMaxMB:        cfg.Log.TotalMaxMB,
		MinFreeMB:         cfg.Log.MinFreeMB,
		Compress:          cfg.Log.Compress,
		AccessMode:        cfg.Log.AccessMode,
		AccessSampleRatio: cfg.Log.AccessSampleRatio,
	})
	if err != nil {
		return err
	}
	defer func() { _ = logger.Close() }()

	log := logger.App()
	log.Info("启动", "version", version.Info())

	// 信号上下文尽早建立：控制台与数据面共用它做优雅退出。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if printBudget {
		fmt.Print(budget.String())
		fmt.Printf("档位来源：%s\n", cfg.ProfileSource)
		if memLimit > 0 {
			fmt.Printf("GOMEMLIMIT：%.0f MiB（GOGC=%d）\n", float64(memLimit)/(1<<20), p.GOGC)
		} else {
			fmt.Printf("GOMEMLIMIT：未设置（可用内存未知，GOGC=%d）\n", p.GOGC)
		}
		return nil
	}

	log.Info("档位已确定",
		"profile", string(cfg.ResolvedProfile),
		"source", cfg.ProfileSource,
		"num_cpu", det.NumCPU,
		"mem_limit_bytes", det.MemBytes,
		"mem_source", det.MemSource,
		"gomemlimit_bytes", memLimit,
		"gogc", p.GOGC,
	)

	// ---- 规则集 ----
	var ruleSet *rules.RuleSet
	if noRules {
		log.Warn("-no-rules：不加载规则集，只做纯转发（仅用于调试）")
	} else {
		ruleSet, err = loadRules(cfg)
		if err != nil {
			return fmt.Errorf("规则集加载失败，拒绝启动（避免出现「以为有防护其实没有」的情况）：%w", err)
		}
		logRuleStats(log, ruleSet)
	}

	// ---- 引擎与流水线 ----
	eng := engine.New(engine.Options{
		RuleSet:          ruleSet,
		Mode:             cfg.Engine.Mode,
		InboundThreshold: cfg.Engine.InboundAnomalyThreshold,
		// mixed 模式的类目阈值。原先这里**没有这一项**，于是 mixed 静默等价于 block
		// 。config 那边现在会强制"mixed 必须配类目阈值"。
		CategoryThresholds: cfg.Engine.CategoryThresholds,
		BanOnBlock:         cfg.Engine.BanOnBlock,
		BlockBanDuration:   cfg.Engine.BlockBanDuration.D(),
		Categories:         rules.DefaultCategories(),
		Limits:             parserLimits(cfg),
		ExpandNestedDocs:   true,
		// 内存事件里保留命中的 payload（可打印化 + 截断），控制台详情页要用。
		// 审计日志里永远不写 payload，两者是分开的。
		CapturePayload: cfg.Admin.Enabled,
	})

	upstream, err := cfg.UpstreamURL()
	if err != nil {
		return fmt.Errorf("上游地址无效：%w", err)
	}
	fwd := proxy.New(proxy.Options{
		Upstream:              upstream,
		PreserveHost:          cfg.Upstream.PreserveHost,
		DialTimeout:           cfg.Upstream.DialTimeout.D(),
		ResponseHeaderTimeout: cfg.Upstream.ResponseHeaderTimeout.D(),
		IdleConnTimeout:       cfg.Upstream.IdleConnTimeout.D(),
		MaxIdleConnsPerHost:   cfg.Upstream.MaxIdleConnsPerHost,
	})
	// ---- 真实 IP ----
	resolver, err := realip.New(realip.Options{
		TrustedProxies: cfg.RealIP.TrustedProxies,
		Header:         cfg.RealIP.Header,
	})
	if err != nil {
		return fmt.Errorf("real_ip 配置无效：%w", err)
	}
	if resolver.TrustedCount() == 0 {
		log.Warn("real_ip.trusted_proxies 为空：一律使用直连对端地址，" +
			"任何 X-Forwarded-For 都会被忽略。若站点前面有反向代理，限速与封禁会把所有流量算成同一个 IP")
	}

	// ---- 限速与封禁 ----
	var limiter *ratelimit.Limiter
	if cfg.RateLimit.Enabled {
		capacity := p.RateLimitTableCapacity
		if cfg.RateLimit.MaxKeys > 0 {
			capacity = cfg.RateLimit.MaxKeys
		}
		limiter, err = ratelimit.New(ratelimit.Options{
			RPS:          float64(cfg.RateLimit.DefaultRPS),
			Burst:        float64(cfg.RateLimit.DefaultBurst),
			BanAfterHits: cfg.RateLimit.BanAfterHits,
			BanWindow:    cfg.RateLimit.BanWindow.D(),
			BanDuration:  cfg.RateLimit.BanDuration.D(),
			Whitelist:    cfg.RateLimit.Whitelist,
			Capacity:     capacity,
		})
		if err != nil {
			return fmt.Errorf("ratelimit 配置无效：%w", err)
		}
	}

	// ---- 过载降级 ----
	degrader := degrade.New(degrade.Options{
		MemLimitBytes: memLimit,
		MaxInflight:   cfg.Listen.MaxConns,
		Mode:          cfg.Engine.Mode,
		Enabled:       cfg.Engine.Degrade != "off",
	})
	degrader.Start()
	defer degrader.Stop()

	// ---- 拦截页 ----
	page, err := loadBlockPage(cfg)
	if err != nil {
		return err
	}
	if page.CustomError() != "" {
		log.Warn("自定义拦截页模板编译失败，已回退内置页面",
			"file", cfg.BlockPage.File, "err", page.CustomError())
	}

	// ---- 内存事件存储（控制台的数据源）----
	var events *eventstore.Store
	if cfg.Admin.Enabled {
		events = eventstore.New(eventstore.Options{
			RingSize:     p.RingBufferSize,
			PayloadLimit: 4 << 10,
		})
	}

	// ---- 告警通道 ----
	notifier := notify.New(notify.Options{
		Enabled:           cfg.Alert.Enabled,
		Webhook:           cfg.Alert.Webhook,
		Instance:          cfg.Upstream.URL,
		AllowPrivateHosts: cfg.Alert.AllowPrivateHosts,
		MinSeverity:       cfg.Alert.MinSeverity,
		Cooldown:          cfg.Alert.Cooldown.D(),
		QueueCap:          cfg.Alert.QueueCap,
	})
	defer notifier.Close()
	if notifier.Enabled() {
		// **绝不把 webhook 原文写进日志**：
		// 钉钉/飞书/Slack 的 webhook URL 里就带着机器人 token，
		// 日志通常比配置文件更容易被读到（收集、转发、贴给同事看）。
		// 这里只打主机名与"配了没配"，够定位问题，也够不出事。
		log.Info("告警通道已启用", "webhook_host", redactWebhookHost(cfg.Alert.Webhook))
	}

	var dataplane http.Handler = fwd
	var pl *pipeline.Pipeline
	if !noRules {
		pl = pipeline.New(pipeline.Options{
			Engine:           eng,
			Next:             fwd,
			Logger:           logger,
			FailMode:         cfg.Engine.FailMode,
			BlockPage:        page,
			Limiter:          limiter,
			Resolver:         resolver,
			Degrader:         degrader,
			BanOnBlock:       cfg.Engine.BanOnBlock,
			BlockBanDuration: cfg.Engine.BlockBanDuration.D(),
			Events:           events,
			Notifier:         notifier,
			AllowedHosts: func(host string) bool {
				return cfg.Upstream.HostAllowed(host)
			},
		})
		dataplane = pl
		log.Info("防护组件已就绪",
			"realip_trusted", resolver.TrustedCount(),
			"ratelimit", cfg.RateLimit.Enabled,
			"ratelimit_rps", cfg.RateLimit.DefaultRPS,
			"ratelimit_capacity", p.RateLimitTableCapacity,
			"degrade", cfg.Engine.Degrade,
			"block_page_custom", page.UsingCustom(),
		)
	}

	// ---- 控制面（所有写操作的唯一入口）----
	var ctl *control.Control
	if !noRules {
		ctl = control.New(control.Options{
			Initial: &control.State{
				Version: "v1",
				Reason:  "启动加载",
				RuleSet: ruleSet,
				BlockPage: control.BlockPageState{
					Options:    page.Options(),
					CustomHTML: page.Options().CustomHTML,
					File:       cfg.BlockPage.File,
					Renderer:   page,
				},
				RateLimit: control.RateLimitState{
					Enabled:      cfg.RateLimit.Enabled,
					RPS:          float64(cfg.RateLimit.DefaultRPS),
					Burst:        float64(cfg.RateLimit.DefaultBurst),
					BanAfterHits: cfg.RateLimit.BanAfterHits,
					BanWindow:    cfg.RateLimit.BanWindow.D(),
					BanDuration:  cfg.RateLimit.BanDuration.D(),
					Whitelist:    cfg.RateLimit.Whitelist,
				},
				DisabledRules: map[string]bool{},
				// 引擎的可热改参数也进 State：这样控制台改模式/阈值走的是
				// 同一条"校验 → 审计 → 原子替换"的路径。
				Engine: control.EngineState{
					Mode:               cfg.Engine.Mode,
					InboundThreshold:   cfg.Engine.InboundAnomalyThreshold,
					CategoryThresholds: cfg.Engine.CategoryThresholds,
					BanOnBlock:         cfg.Engine.BanOnBlock,
					BlockBanDuration:   cfg.Engine.BlockBanDuration.D(),
				},
			},
			Applier: &applier{engine: eng, pipeline: pl, limiter: limiter, logger: logger},
		})
	}

	srv := server.New(server.Options{
		Config:        cfg,
		Profile:       p,
		ProfileName:   cfg.ResolvedProfile,
		ProfileSource: cfg.ProfileSource,
		Budget:        budget,
		Detection:     det,
		MemLimit:      memLimit,
		Logger:        logger,
		Next:          dataplane,
		Version:       version.Version,
		Ruleset:       rulesetSummary(ruleSet),
		DegradeInfoFn: func() *server.DegradeInfo {
			ds := degrader.Stats()
			return &server.DegradeInfo{
				Level:        ds.Level,
				LevelNum:     ds.LevelNum,
				Reason:       ds.Reason,
				HeapRatio:    ds.HeapRatio,
				GCCPUFrac:    ds.GCCPUFrac,
				Inflight:     ds.Inflight,
				RejectsRate:  ds.RejectsRate,
				ShouldReject: ds.ShouldReject,
				Transitions:  ds.Transitions,
			}
		},
	})
	// ---- 控制台（独立端口、独立 mux、不进检测引擎）----
	if cfg.Admin.Enabled {
		if ctl == nil {
			return fmt.Errorf("admin.enabled 需要规则集（不要同时使用 -no-rules）")
		}
		cs, initialPW, err := console.New(console.Options{
			Config:   cfg,
			Control:  ctl,
			Events:   events,
			Limiter:  limiter,
			Resolver: resolver,
			Logger:   logger,
			Version:  version.Version,
			Notifier: notifier,
			ApplyNotifier: func(n *notify.Notifier) {
				if pl != nil {
					pl.SetNotifier(n)
				}
			},
			// 控制台的 /status 与数据面的 /readyz 共用同一份就绪事实，
			// 避免两边各算一遍后出现"控制台说 A、readyz 说 B"。
			ReadyInfo: srv.ReadyMap,
			EventSummary: func() map[string]any {
				out := map[string]any{}
				if pl != nil {
					st := pl.Stats()
					out["blocked"] = st.Blocked
					out["rate_limited"] = st.RateLimited
					out["rejected_503"] = st.Rejected503
					out["engine_errors"] = st.EngineErrors
					out["tarpitted"] = st.Tarpitted
				}
				if degrader != nil {
					ds := degrader.Stats()
					out["degrade_level"] = ds.Level
					// 数字形式也要给：控制台把它当数值比较（0=正常），
					// 只给 "L0-normal" 这种字符串会被当成 null，
					// 于是正常状态被误显示成"系统处于降级状态 L?"。
					out["degrade_level_num"] = ds.LevelNum
					out["degrade_reason"] = ds.Reason
					out["degrade_reject"] = ds.ShouldReject
				}
				return out
			},
		})
		if err != nil {
			return fmt.Errorf("控制台启动失败：%w", err)
		}
		go func() {
			if err := serveConsole(ctx, cs, logger); err != nil {
				log.Error("控制台退出", "err", err)
			}
		}()
		log.Info("控制台已启动",
			"addr", cfg.Admin.Addr, "mount", cs.Mount(),
			"tls", cfg.Admin.TLS.Enabled, "gate", cfg.Admin.Gate.Enabled)
		// 门槛是否真的启用：enabled 与 mode 都要看（mode=none 表示明确不要门槛）。
		gateOn := cfg.Admin.Gate.Enabled && cfg.Admin.Gate.Mode != "none"
		gateUser := firstNonEmpty(cfg.Admin.Gate.Username, "gate")

		if initialPW != "" {
			// 初始口令只在这里打印一次，**不写进配置文件**（绝不使用默认口令）。
			log.Warn("控制台初始登录口令（仅本次启动有效，请立即登录后修改）",
				"username", firstNonEmpty(cfg.Admin.Username, "admin"),
				"password", initialPW,
				"login_url", cs.URL())
			// 门槛用的是**另一套用户名**，必须单独印一行。
			//
			// 只印上面那行会把运维带沟里：浏览器弹的是 Basic 框，而上面写的用户名是
			// admin（那是第二层登录页的用户名）。照着填只会一直 401，且没有任何
			// 提示说该用 gate。这里把门槛那一行的用户名与同一个口令并排印出来。
			if gateOn {
				log.Warn("门槛凭据（HTTP Basic，仅本次启动有效）",
					"username", gateUser,
					"password", initialPW,
					"note", "浏览器弹的 Basic 框填这一行；进页面后再用上面那行的用户名登录")
			}
		}
	}

	return srv.Serve(ctx)
}

// runHashPasswordCmd 生成控制台登录口令的哈希，供写进 admin.password_hash。
//
// 为什么必须有这个子命令：配置里要的是 `pbkdf2-sha256$…` 形式的哈希，
// 而在此之前**没有任何受支持的生成方式** —— 控制台改口令的接口只把哈希留在内存里、
// 不回显，配置注释却写着"留空则打印生成哈希的命令"（实际留空是随机口令）。
// 结果就是运维按文档做不下去。这是补上的那一步。
//
// 口令**只从标准输入读**，不接受命令行参数：参数会进 shell 历史与 ps 输出。
func runHashPasswordCmd(args []string) int {
	for _, a := range args {
		switch a {
		case "-h", "--help", "help":
			fmt.Fprint(os.Stderr, `用法：donothack hash-password

从标准输入读一行口令，把 pbkdf2-sha256 哈希打到标准输出，供写进
config.yaml 的 admin.password_hash（控制台登录）或 admin.gate.password_hash
（第一层 Basic 门槛，另一套凭据）。口令至少 12 位。

交互输入：
  donothack hash-password

管道输入（口令不回显）：
  echo -n '你的口令' | donothack hash-password

口令不能作为命令行参数传入：参数会进 shell 历史与 ps 输出。
`)
			return 0
		default:
			fmt.Fprintf(os.Stderr, "donothack: hash-password 不接受参数 %q（口令请从标准输入给）\n", a)
			return 2
		}
	}

	fmt.Fprintln(os.Stderr, "请输入控制台登录口令（至少 12 位，回车结束）。")
	fmt.Fprintln(os.Stderr, "提示：输入会回显，请在可信终端操作；也可以用管道喂进来：")
	fmt.Fprintln(os.Stderr, "  echo -n '你的口令' | donothack hash-password")
	fmt.Fprint(os.Stderr, "口令：")

	rd := bufio.NewReader(os.Stdin)
	pw, err := rd.ReadString('\n')
	if err != nil && pw == "" {
		fmt.Fprintf(os.Stderr, "donothack: 读取口令失败：%v\n", err)
		return 1
	}
	pw = strings.TrimRight(pw, "\r\n")

	if len(pw) < 12 {
		fmt.Fprintln(os.Stderr, "donothack: 口令至少 12 位（与控制台改口令的校验一致）")
		return 1
	}
	hash, err := console.HashPassword(pw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "donothack: 生成哈希失败：%v\n", err)
		return 1
	}
	// 只把哈希打到标准输出，方便直接重定向/复制；提示语都走 stderr。
	fmt.Println(hash)
	return 0
}

func loadRules(cfg *config.Config) (*rules.RuleSet, error) {
	opts := rules.DefaultOptions()
	opts.SelfTest = cfg.Rules.SelfTest
	opts.MaxRules = cfg.Limits.MaxRules
	opts.MaxPMPatterns = cfg.Limits.MaxPrefilterLiterals
	opts.FileBase = cfg.Rules.Dir
	return rules.LoadDir(opts, cfg.Rules.Dir, cfg.Rules.Files)
}

func parserLimits(cfg *config.Config) parser.Limits {
	return parser.Limits{
		MaxParams:       cfg.Limits.MaxParams,
		MaxParamValLen:  int(cfg.Limits.MaxParamValueLen),
		MaxURILength:    cfg.Limits.MaxURILength,
		MaxHeaders:      cfg.Limits.MaxHeaders,
		MaxInspectBody:  int(cfg.Limits.MaxInspectBody),
		MaxJSONDepth:    cfg.Limits.MaxJSONDepth,
		MaxJSONNodes:    cfg.Limits.MaxJSONNodes,
		MaxNestedDecode: cfg.Limits.MaxTransformDepth,
	}
}

func logRuleStats(log interface {
	Info(string, ...any)
}, rs *rules.RuleSet) {
	if rs == nil {
		return
	}
	st := rs.Stats()
	log.Info("规则集已加载",
		"version", rs.Version,
		"files", st.Files,
		"rules", st.Rules,
		"enabled", st.Enabled,
		"disabled", st.Disabled,
		"chains", st.Chains,
		"literal_rules", st.LiteralRules,
		"no_literal_rules", st.NoLiteralRules,
		"prefilter_nodes", st.PrefilterNodes,
	)
	for _, w := range st.Warnings {
		log.Info("规则集告警", "warn", w)
	}
}

func rulesetSummary(rs *rules.RuleSet) string {
	if rs == nil {
		return "未加载（-no-rules）"
	}
	st := rs.Stats()
	return fmt.Sprintf("%s（%d 条启用 / %d 条总数，%d 条变换链，预筛节点 %d）",
		rs.Version, st.Enabled, st.Rules, st.Chains, st.PrefilterNodes)
}

// ---------------------------------------------------------------- rules check / test

func runRulesCmd(args []string) int {
	fs := flag.NewFlagSet("rules check", flag.ExitOnError)
	dir := fs.String("d", "./rules", "规则目录")
	selfTest := fs.Bool("self-test", true, "是否跑规则自带的正负样本")
	_ = fs.Parse(args)

	opts := rules.DefaultOptions()
	opts.SelfTest = *selfTest
	opts.FileBase = *dir

	rs, err := rules.LoadDir(opts, *dir, []string{"*.yaml", "*.yml"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "规则集校验失败：\n%v\n", err)
		return 1
	}
	st := rs.Stats()
	fmt.Printf("规则集校验通过\n")
	fmt.Printf("  版本      : %s\n", rs.Version)
	fmt.Printf("  文件      : %d\n", st.Files)
	fmt.Printf("  规则      : %d（启用 %d / 禁用 %d）\n", st.Rules, st.Enabled, st.Disabled)
	fmt.Printf("  变换链    : %d 条（去重后）\n", st.Chains)
	fmt.Printf("  可预筛    : %d 条；无字面量必须每请求评估 %d 条；短字面量被排除 %d 条\n",
		st.LiteralRules, st.NoLiteralRules, st.ShortLiterals)
	fmt.Printf("  预筛节点  : %d\n", st.PrefilterNodes)
	fmt.Printf("  例外      : %d 条\n", len(rs.Exceptions()))
	fmt.Printf("  类目分布  : ")
	first := true
	for cat, n := range st.ByCategory {
		if !first {
			fmt.Printf("、")
		}
		fmt.Printf("%s=%d", cat, n)
		first = false
	}
	fmt.Println()
	if *selfTest {
		fmt.Printf("  自测      : 全部正负样本通过\n")
	}
	for _, w := range st.Warnings {
		fmt.Printf("  告警      : %s\n", w)
	}
	return 0
}

// ---------------------------------------------------------------- test -r

func runTestCmd(args []string) int {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	reqFile := fs.String("r", "", "原始 HTTP 请求报文文件")
	dir := fs.String("d", "./rules", "规则目录")
	verbose := fs.Bool("v", false, "输出变换前后的值")
	_ = fs.Parse(args)

	if strings.TrimSpace(*reqFile) == "" {
		fmt.Fprintln(os.Stderr, "用法：donothack test -r req.http [-d ./rules] [-v]")
		return 2
	}

	raw, err := os.ReadFile(*reqFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取请求报文失败：%v\n", err)
		return 1
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析请求报文失败（需要标准 HTTP 报文格式）：%v\n", err)
		return 1
	}
	req.RemoteAddr = "127.0.0.1:0"

	opts := rules.DefaultOptions()
	opts.FileBase = *dir
	rs, err := rules.LoadDir(opts, *dir, []string{"*.yaml", "*.yml"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "规则集加载失败：\n%v\n", err)
		return 1
	}

	eng := engine.New(engine.Options{
		RuleSet:          rs,
		Mode:             "detect",
		InboundThreshold: 5,
		Categories:       rules.DefaultCategories(),
		Limits:           parser.DefaultLimits(),
		ExpandNestedDocs: true,
	})

	t := &tx.Transaction{}
	dec, err := eng.Process(context.Background(), t, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "检测出错：%v\n", err)
		return 1
	}

	fmt.Printf("=== 离线检测 ===\n")
	fmt.Printf("请求      : %s %s %s\n", t.Vars.Method, t.Vars.URI, t.Vars.Proto)
	fmt.Printf("路径      : 原始 %q → 规范化 %q\n", t.Vars.RawPath, t.Vars.Path)
	fmt.Printf("参数      : ARGS %d 个 / GET %d / POST %d / JSON %d / XML %d\n",
		t.Vars.Args.Len(), t.Vars.ArgsGet.Len(), t.Vars.ArgsPost.Len(),
		t.Vars.ArgsJSON.Len(), t.Vars.ArgsXML.Len())
	if len(t.Vars.ParseErrors) > 0 {
		fmt.Printf("解析异常  : %v\n", t.Vars.ParseErrors)
	}
	fmt.Printf("分数      : %d\n", dec.Score)
	fmt.Printf("裁决      : %s（模式 %s：%s）\n", dec.Verdict, dec.Mode, dec.Reason)
	if len(dec.Events) == 0 {
		fmt.Printf("命中      : 无\n")
		return 0
	}
	fmt.Printf("命中 %d 条：\n", len(dec.Events))
	for _, ev := range dec.Events {
		fmt.Printf("  %-14s %-9s %-10s %-22s %s\n",
			ev.RuleID, ev.Category, ev.Severity, ev.Target, ev.Detail)
	}
	if *verbose {
		fmt.Printf("\n=== 变换链路（逐条规则）===\n")
		traceHits(rs, t, dec)
	}
	return 0
}

// traceHits 打印请求里的参数值（可打印化后），用于调误报。
//
// 只在离线命令里做：运行期不会为了调试而遍历参数。
func traceHits(_ *rules.RuleSet, t *tx.Transaction, dec engine.Decision) {
	fmt.Printf("请求参数（可打印化，最多 200 字节/值）：\n")
	t.Vars.Args.ForEach(func(k, v []byte) bool {
		fmt.Printf("  %s = %s\n", k, printable(v))
		return true
	})
	if len(dec.Events) > 0 {
		fmt.Printf("命中规则的变换链见各规则定义；用 -v 时此处只展示输入值，避免把 payload 拼进日志\n")
	}
}

func printable(b []byte) string {
	const maxLen = 200
	var sb strings.Builder
	for i, c := range b {
		if i >= maxLen {
			sb.WriteString("…")
			break
		}
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
			continue
		}
		fmt.Fprintf(&sb, "\\x%02x", c)
	}
	if sb.Len() == 0 {
		return "(空)"
	}
	return sb.String()
}

var _ = io.Discard
var _ = filepath.Join

// loadBlockPage 构造拦截页渲染器。
//
// 自定义模板从磁盘读（控制台保存时写的就是这个文件）。**读失败不是致命错误** ——
// 拦截页是兜底路径，它自己不能成为启动失败的原因；回退内置页并留痕即可。
func loadBlockPage(cfg *config.Config) (*blockpage.Renderer, error) {
	o := blockpage.Options{
		Status:      cfg.BlockPage.Status,
		Branding:    cfg.BlockPage.BrandingOn(),
		ProductName: cfg.BlockPage.ProductName,
		ProductURL:  cfg.BlockPage.ProductURL,
		Contact:     cfg.BlockPage.Contact,
		Title:       cfg.BlockPage.Title,
		Version:     version.Version,
	}
	if f := strings.TrimSpace(cfg.BlockPage.File); f != "" {
		path := f
		if !filepath.IsAbs(path) && cfg.Path != "" {
			path = filepath.Join(filepath.Dir(cfg.Path), path)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			// 文件不存在：可能是"还没在控制台里配过"，不算错误。
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("读取自定义拦截页失败：%w", err)
			}
		} else {
			o.CustomHTML = string(raw)
		}
	}
	return blockpage.New(o), nil
}

// applier 把控制面的新状态推给数据面。
//
// 全部是原子替换，**绝不能阻塞** —— 控制台的慢操作不许影响转发。
type applier struct {
	engine   *engine.Engine
	pipeline *pipeline.Pipeline
	limiter  *ratelimit.Limiter
	logger   *audit.Logger
}

func (a *applier) ApplyRuleset(rs *rules.RuleSet) {
	if a.engine != nil {
		a.engine.Swap(rs)
	}
}

func (a *applier) ApplyBlockPage(r *blockpage.Renderer, _ blockpage.Options) {
	if a.pipeline != nil {
		a.pipeline.SetBlockPage(r)
	}
}

func (a *applier) ApplyExceptions(list []*rules.Exception) {
	if a.engine != nil {
		a.engine.SetExceptions(list)
	}
}

func (a *applier) ApplyIPLists(st control.IPListState) {
	if a.pipeline == nil {
		return
	}
	if err := a.pipeline.SetIPLists(st.Allow, st.Deny, st.DenyStatus); err != nil && a.logger != nil {
		a.logger.App().Error("IP 名单应用失败", "err", err)
	}
}

// ApplyEngine 把热改参数推给引擎（模式/阈值/命中即封禁）。
//
// 这条路径是"应急切 block"真正生效的地方：
// 原先控制台返回"已热改"而引擎根本没收到，WAF 继续在 detect 放行。
func (a *applier) ApplyEngine(st control.EngineState) {
	if a.engine == nil {
		return
	}
	a.engine.SetTunables(engine.Tunables{
		Mode:               st.Mode,
		InboundThreshold:   st.InboundThreshold,
		CategoryThresholds: st.CategoryThresholds,
		BanOnBlock:         st.BanOnBlock,
		BlockBanDuration:   st.BlockBanDuration,
	})
}

func (a *applier) ApplyRateLimit(st control.RateLimitState) {
	if a.limiter == nil {
		return
	}
	// 参数不合法时保留旧参数（校验已在控制面做过，这里只兜底）
	_ = a.limiter.Reconfigure(ratelimit.Options{
		RPS:          st.RPS,
		Burst:        st.Burst,
		BanAfterHits: st.BanAfterHits,
		BanWindow:    st.BanWindow,
		BanDuration:  st.BanDuration,
		Whitelist:    st.Whitelist,
	})
}

// serveConsole 在独立端口上跑控制台。
//
// 与数据面完全分离：独立监听、独立 mux、独立限流与认证。
// 控制台流量**不进检测引擎** —— 否则管理员改规则时可能被自己的规则拦掉。
func serveConsole(ctx context.Context, cs *console.Server, logger *audit.Logger) error {
	tlsCfg, err := cs.TLSConfig()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cs.Addr(),
		Handler:           cs.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// 控制台不做 TLS 时会有敏感凭据走明文，必须显式确认过才允许非本机绑定。
	if tlsCfg == nil && !isLoopbackAddr(cs.Addr()) && !cs.AllowInsecure() {
		return fmt.Errorf("控制台绑定在非本机地址 %s 但未启用 TLS；"+
			"Basic 门槛凭据是 base64 不是加密，请启用 admin.tls 或显式设置 admin.allow_insecure: true", cs.Addr())
	}

	errCh := make(chan error, 1)
	go func() {
		var e error
		if tlsCfg != nil {
			e = srv.ListenAndServeTLS("", "")
		} else {
			e = srv.ListenAndServe()
		}
		errCh <- e
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

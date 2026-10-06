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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"donothack/internal/audit"
	"donothack/internal/blockpage"
	"donothack/internal/config"
	"donothack/internal/degrade"
	"donothack/internal/engine"
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

func main() {
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "rules":
			os.Exit(runRulesCmd(args[1:]))
		case "test":
			os.Exit(runTestCmd(args[1:]))
		case "version":
			fmt.Println(version.Info())
			return
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

func usage() {
	fmt.Fprint(os.Stderr, `donothack —— 请求侧 Web 应用防火墙

用法：
  donothack -c config.yaml              启动数据面
  donothack rules check -d ./rules      校验规则集
  donothack rules test  -d ./rules      跑规则自带的正负样本
  donothack test -r req.http            离线跑一条原始请求
  donothack version                     打印版本
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
		Categories:       rules.DefaultCategories(),
		Limits:           parserLimits(cfg),
		ExpandNestedDocs: true,
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

	var dataplane http.Handler = fwd
	if !noRules {
		dataplane = pipeline.New(pipeline.Options{
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
		})
		log.Info("防护组件已就绪",
			"realip_trusted", resolver.TrustedCount(),
			"ratelimit", cfg.RateLimit.Enabled,
			"ratelimit_rps", cfg.RateLimit.DefaultRPS,
			"ratelimit_capacity", p.RateLimitTableCapacity,
			"degrade", cfg.Engine.Degrade,
			"block_page_custom", page.UsingCustom(),
		)
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
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return srv.Serve(ctx)
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

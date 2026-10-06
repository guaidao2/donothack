// Command donothack 是 WAF 的数据面进程。
//
// P0 范围：加载配置 → 探测档位 → 设置 GC 参数 → 打印内存预算 → 启动反向代理 → 优雅停机。
// 检测引擎（解析层、规则集、评分与动作）从 P1 开始接入。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"donothack/internal/audit"
	"donothack/internal/config"
	"donothack/internal/profile"
	"donothack/internal/proxy"
	"donothack/internal/server"
	"donothack/internal/version"
)

func main() {
	var (
		cfgPath    = flag.String("c", "config.yaml", "配置文件路径")
		showVer    = flag.Bool("version", false, "打印版本后退出")
		checkCfg   = flag.Bool("check-config", false, "只校验配置后退出")
		showBudget = flag.Bool("print-budget", false, "打印档位与内存预算表后退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version.Info())
		return
	}

	if err := run(*cfgPath, *checkCfg, *showBudget); err != nil {
		fmt.Fprintf(os.Stderr, "donothack: %v\n", err)
		os.Exit(1)
	}
}

func run(cfgPath string, checkOnly, printBudget bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	p := profile.Get(cfg.ResolvedProfile)
	det := cfg.Detection

	// GOGC 与 GOMEMLIMIT 必须配合使用：单独抬 GOGC 内存会无限涨，
	// 单独设上限而 GOGC 保持 100 会让 GC 过频白烧 CPU。
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

	// 硬约束：并发连接 × 每连接预算 + 规则集 + 池 必须小于可用内存的 60%。
	// 内存探测不到时只打印提示，不阻塞启动。见 docs/PERFORMANCE.md §2.3。
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

	// 打印档位与预算：这一段是排查"为什么规则/连接被限住"的第一手信息。
	log.Info("档位已确定",
		"profile", string(cfg.ResolvedProfile),
		"source", cfg.ProfileSource,
		"num_cpu", det.NumCPU,
		"cpu_source", det.CPUSource,
		"mem_limit_bytes", det.MemBytes,
		"mem_source", det.MemSource,
		"gomemlimit_bytes", memLimit,
		"gogc", p.GOGC,
	)
	for _, line := range budgetLines(budget) {
		log.Debug("内存预算", "item", line.Label, "mib", line.MiB)
	}
	log.Info("内存预算合计",
		"total_mib", budget.TotalMiB,
		"target_mib", budget.TargetMiB,
		"console_mib", p.ConsoleMemBudgetMiB,
	)

	upstream, err := cfg.UpstreamURL()
	if err != nil {
		return fmt.Errorf("上游地址无效：%w", err)
	}

	h := proxy.New(proxy.Options{
		Upstream:              upstream,
		PreserveHost:          cfg.Upstream.PreserveHost,
		DialTimeout:           cfg.Upstream.DialTimeout.D(),
		ResponseHeaderTimeout: cfg.Upstream.ResponseHeaderTimeout.D(),
		IdleConnTimeout:       cfg.Upstream.IdleConnTimeout.D(),
		MaxIdleConnsPerHost:   cfg.Upstream.MaxIdleConnsPerHost,
	})

	srv := server.New(server.Options{
		Config:        cfg,
		Profile:       p,
		ProfileName:   cfg.ResolvedProfile,
		ProfileSource: cfg.ProfileSource,
		Budget:        budget,
		Detection:     det,
		MemLimit:      memLimit,
		Logger:        logger,
		Next:          h,
		Version:       version.Version,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return srv.Serve(ctx)
}

func budgetLines(b profile.Budget) []profile.BudgetItem { return b.Items }

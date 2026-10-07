package console

import (
	"net/http"
	"time"

	"donothack/internal/config"
	"donothack/internal/control"
)

// 本文件实现引擎热参数的读写入口：GET / PUT /api/v1/engine。
//
// 为什么单开一个端点，而不是让前端去 PUT /config：
// WAF 的配置里大部分项改不了（监听、上游、TLS、real_ip 都要重建组件），
// 所以整份 PUT /config 是被**有意拒绝**的（见 api_config.go 顶部）。
// 但"切模式"偏偏是运维最常用的动作 —— 发现攻击已经在打，要把 detect 立刻改成 block。
// 在这之前，控制台页面上根本没有入口：只能去磁盘改 config.yaml 再点重载，
// 而"编辑运行配置"那个对话框点保存必然 405 —— 一条走不通的死路。
//
// 这里给引擎参数一个专用入口，走与 reload 完全相同的 control.Apply：
// 校验 → 审计 → 原子替换 → 失败回滚，改不了的东西绝不静默忽略。

func (s *Server) handleEngine(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 读引擎参数同样要会话。这里曾经漏挂 —— 匿名就能拿到 mode / 阈值 /
		// 封禁时长，等于把防护档位直接告诉攻击者（用来校准节奏）。
		if !s.requireRead(w, r) {
			return
		}
		s.engineRead(w)
	case http.MethodPut, http.MethodPost:
		s.engineWrite(w, r)
	default:
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只支持 GET 与 PUT", "")
	}
}

func (s *Server) engineRead(w http.ResponseWriter) {
	snap := s.o.Control.Snapshot()
	if snap == nil {
		s.writeError(w, http.StatusServiceUnavailable, "no_snapshot", "控制面尚未初始化", "")
		return
	}
	writeJSON(w, http.StatusOK, enginePayload(snap.Engine))
}

// enginePayload 是给前端的统一形状：字段名与 control.SetEngine 的入参一致，
// 免得前端在两个页面里各拼一套。
func enginePayload(e control.EngineState) map[string]any {
	cats := map[string]int{}
	for k, v := range e.CategoryThresholds {
		cats[k] = v
	}
	return map[string]any{
		"ok":                        true,
		"mode":                      e.Mode,
		"inbound_anomaly_threshold": e.InboundThreshold,
		"category_thresholds":       cats,
		"ban_on_block":              e.BanOnBlock,
		"block_ban_duration_s":      int(e.BlockBanDuration.Seconds()),
	}
}

func (s *Server) engineWrite(w http.ResponseWriter, r *http.Request) {
	if !s.requireWrite(w, r) {
		return
	}
	var req struct {
		// 指针表示"这次要改它"；nil = 保持不动。与 control.SetEngine 的约定一致。
		Mode               *string        `json:"mode"`
		InboundThreshold   *int           `json:"inbound_anomaly_threshold"`
		CategoryThresholds map[string]int `json:"category_thresholds"`
		BanOnBlock         *bool          `json:"ban_on_block"`
		BlockBanDurationS  *int           `json:"block_ban_duration_s"`
	}
	if err := decodeJSON(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", "请求体不是合法 JSON", err.Error())
		return
	}
	if req.Mode == nil && req.InboundThreshold == nil && req.CategoryThresholds == nil &&
		req.BanOnBlock == nil && req.BlockBanDurationS == nil {
		// 一个字段都没给：当成读操作回答，而不是"改成功" ——
		// 静默成功会让"我明明点保存了"变成一个查不出来的错觉。
		s.engineRead(w)
		return
	}

	mut := control.SetEngine{
		Mode:             req.Mode,
		InboundThreshold: req.InboundThreshold,
		BanOnBlock:       req.BanOnBlock,
	}
	if req.CategoryThresholds != nil {
		mut.CategoryThresholds = req.CategoryThresholds
	}
	if req.BlockBanDurationS != nil {
		d := time.Duration(*req.BlockBanDurationS) * time.Second
		mut.BlockBanDuration = &d
	}

	sess, _ := s.currentSession(r)
	next, warnings, err := s.o.Control.Apply(mut, actorOf(sess, r), s.clientIP(r))
	if err != nil {
		// 校验不过 ⇒ 控制面保持旧状态，数据面完全没动。这里要如实说清"没改"。
		s.writeError(w, http.StatusUnprocessableEntity, "apply_failed",
			"引擎参数应用失败，已回滚（当前运行参数未改变）", err.Error())
		return
	}
	out := enginePayload(next.Engine)
	out["warnings"] = warnings
	// **把热改结果同步回内存里的配置对象。**
	//
	// 这一步必须做：`/status`、`/config` 以及"磁盘 vs 运行中"的差异都读内存里的
	// Config 对象。不同步就会出现"运行模式卡写着 block、概览还写着 detect"这种
	// 两个真值来源各说各话的情况（实测被指出来过）。
	//
	// 注意这只是内存视图：磁盘上的 config.yaml 没动，重启会回到文件里的值 ——
	// 差异页会如实显示这一点，这正是我们想让人看到的。
	syncEngineConfig(s.o.Config, next.Engine)
	writeJSON(w, http.StatusOK, out)
}

// syncEngineConfig 把控制面里的引擎热参数写回内存配置对象。
func syncEngineConfig(cfg *config.Config, e control.EngineState) {
	if cfg == nil {
		return
	}
	cfg.Engine.Mode = e.Mode
	cfg.Engine.InboundAnomalyThreshold = e.InboundThreshold
	cfg.Engine.BanOnBlock = e.BanOnBlock
	cfg.Engine.BlockBanDuration = config.Duration(e.BlockBanDuration)
	// 类目阈值整份替换：热改的语义就是"这次给的就是全部"。
	// 空则清掉，免得磁盘上已删掉的类目在内存里留着。
	if len(e.CategoryThresholds) == 0 {
		cfg.Engine.CategoryThresholds = nil
		return
	}
	cats := make(map[string]int, len(e.CategoryThresholds))
	for k, v := range e.CategoryThresholds {
		cats[k] = v
	}
	cfg.Engine.CategoryThresholds = cats
}

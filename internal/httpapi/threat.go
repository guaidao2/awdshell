package httpapi

import (
	"net/http"
	"strings"
)

// 态势时间窗的取值范围：下限 1 天（0 或负数会算出未来的 since，窗口恒空），
// 上限 365 天（service.ThreatService.Stats 的夹取上限，再大也只是被它夹回来）。
const (
	defaultThreatDays = 7
	maxThreatDays     = 365
)

// handleThreat 处理 /api/threat/*：
//
//	GET /api/threat/stats?days=7   态势聚合
//	GET /api/threat/count          累计事件数
func (s *Server) handleThreat(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/threat/")

	// 只读 action 明确只允许 GET，写 action 明确只允许 POST：
	// Go 的 GET 也能带 body，prune 之前没有方法校验，裸 GET 就能删事件表。
	switch action {
	case "stats", "count":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	default:
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}

	switch action {
	case "stats":
		// days 解析失败要如实回 400：以前用 fmt.Sscanf 且不判返回值，
		// `days=abc` 会静默落回默认的 7 天 —— 用户以为自己设了别的时间窗，
		// 界面上却一点提示都没有。与 /api/logs/scan 的 lines 同一套判据。
		// 范围与 service 侧一致（service.ThreatService.Stats 把 days 夹到 [1,365]）：
		// days<=0 会算出**未来**的 since，得到一个恒为空的窗口（复审实测
		// days=-1 → 200 + since=1791078910037）；>365 被 service 静默夹回 365，
		// 用户以为查了三年、实际只查了一年。两种都在这里挡掉。
		days, err := queryIntRange(r.URL.Query(), "days", defaultThreatDays, 1, maxThreatDays)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		// target_id 可选：带上就只看这台主机的态势
		st, err := s.Threat.Stats(days, r.URL.Query().Get("target_id"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, st)

	case "prune":
		// 按设置里的保留天数立刻清理一次
		cfg := s.Settings.Get()
		n, err := s.Threat.PruneEvents(cfg.EventKeepDays)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		left, _ := s.Threat.EventCount()
		writeJSON(w, http.StatusOK, map[string]any{"deleted": n, "left": left})

	case "clear":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		n, err := s.Threat.ClearEvents()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": n, "left": 0})

	case "count":
		n, err := s.Threat.EventCount()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]int{"count": n})

	default:
		http.NotFound(w, r)
	}
}

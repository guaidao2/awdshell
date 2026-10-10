package httpapi

import (
	"fmt"
	"net/http"
	"strings"
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
		days := 7
		if v := r.URL.Query().Get("days"); v != "" {
			fmt.Sscanf(v, "%d", &days)
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

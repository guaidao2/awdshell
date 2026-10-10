package httpapi

import (
	"net/http"

	"github.com/guaidao2/awdshell/internal/service"
)

// handleSettings 读写用户设置。
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.Settings.Get())

	case http.MethodPost:
		var in service.Settings
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, s.Settings.Update(in))

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// handlePruneNow 立即执行一次连接历史清理（设置页的"立即清理"按钮）。
func (s *Server) handlePruneNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg := s.Settings.Get()
	n, err := s.Store.PruneConnections(cfg.ConnKeepDays, cfg.ConnKeepMax)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": n})
}

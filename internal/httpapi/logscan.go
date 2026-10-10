package httpapi

import (
	"fmt"
	"net/http"
	"strings"
)

// handleLogs 处理 /api/logs/*：探测日志文件与扫描攻击载荷。
func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/logs/")
	targetID := r.URL.Query().Get("target_id")
	if targetID == "" {
		writeErr(w, http.StatusBadRequest, errText("缺少 target_id"))
		return
	}

	switch action {
	case "files":
		files, err := s.Logs.ListLogFiles(targetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, files)

	case "scan":
		lines := 2000
		if v := r.URL.Query().Get("lines"); v != "" {
			fmt.Sscanf(v, "%d", &lines)
		}
		res, err := s.Logs.ScanLog(targetID, r.URL.Query().Get("path"), lines, r.URL.Query().Get("kind"))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, res)

	default:
		http.NotFound(w, r)
	}
}

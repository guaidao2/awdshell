package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// handleCompliance 处理 /api/compliance/*：
//
//	GET  /api/compliance/checks  列出检查项
//	POST /api/compliance/run     在目标机上执行核查
func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/compliance/")

	switch action {
	case "checks":
		checks, problems, err := s.Compliance.Checks()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"checks": checks, "problems": problems})

	case "run":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			TargetID string   `json:"target_id"`
			Only     []string `json:"only"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, errText("请求体解析失败"))
			return
		}
		if strings.TrimSpace(body.TargetID) == "" {
			writeErr(w, http.StatusBadRequest, errText("缺少 target_id"))
			return
		}
		report, err := s.Compliance.Run(body.TargetID, body.Only)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, report)

	case "history":
		list, err := s.Compliance.History(r.URL.Query().Get("target_id"), 30)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"reports": list})

	case "report":
		var id int64
		fmt.Sscanf(r.URL.Query().Get("id"), "%d", &id)
		if id <= 0 {
			writeErr(w, http.StatusBadRequest, errText("缺少 id"))
			return
		}
		rep, err := s.Compliance.ReportByID(id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if rep == nil {
			writeErr(w, http.StatusNotFound, errText("找不到这份报告"))
			return
		}
		writeJSON(w, http.StatusOK, rep)

	default:
		http.NotFound(w, r)
	}
}

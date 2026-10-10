package httpapi

import (
	"encoding/json"
	"net/http"
)

// handleHostKeys 处理已记录的主机密钥：
//
//	GET  /api/hostkeys?target_id=   查询某目标记录的主机密钥
//	POST /api/hostkeys/forget       清除某目标的记录（确认对端换过密钥后用）
func (s *Server) handleHostKeys(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/hostkeys":
		targetID := r.URL.Query().Get("target_id")
		if targetID == "" {
			writeErr(w, http.StatusBadRequest, errText("缺少 target_id"))
			return
		}
		info, err := s.Targets.HostKeyInfo(targetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"host_key": info})

	case "/api/hostkeys/forget":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			TargetID string `json:"target_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TargetID == "" {
			writeErr(w, http.StatusBadRequest, errText("缺少 target_id"))
			return
		}
		removed, err := s.Targets.ForgetHostKey(body.TargetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"removed": removed,
			"note": "下次连接会重新记录该主机的主机密钥"})

	default:
		http.NotFound(w, r)
	}
}

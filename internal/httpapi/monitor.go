package httpapi

import "net/http"

// handleMonitor 采样一次目标主机的资源指标（CPU/内存/磁盘/网络/进程/监听端口）。
func (s *Server) handleMonitor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	targetID := r.URL.Query().Get("target_id")
	if targetID == "" {
		writeErr(w, http.StatusBadRequest, errText("缺少 target_id"))
		return
	}
	m, err := s.Monitor.Sample(targetID)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

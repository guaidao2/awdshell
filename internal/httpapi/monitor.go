package httpapi

import (
	"errors"
	"net/http"

	"github.com/guaidao2/awdshell/internal/service"
)

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
		writeErr(w, monitorErrStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// monitorErrStatus 把采样错误映射成状态码。
//
// service.ErrSampling 是"这个目标上一次采样还没结束"，属于**并发拒绝**：
// 客户端该做的是跳过这一轮，不是报故障。以前它和真实采集错误一起回 502，
// 界面把它画成红色的"采集失败"（审计 M1）—— 用户在 A/B 之间切一下就中招。
// 409 Conflict 的语义正是"请求本身没毛病，只是与当前状态冲突"。
func monitorErrStatus(err error) int {
	if errors.Is(err, service.ErrSampling) {
		return http.StatusConflict
	}
	return http.StatusBadGateway
}

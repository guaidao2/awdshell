package httpapi

import (
	"errors"
	"io"
	"net/http"
)

// handleHostKeys 处理已记录的主机密钥：
//
//	GET  /api/hostkeys?target_id=   查询某目标记录的主机密钥
//	POST /api/hostkeys/forget       清除某目标的记录（确认对端换过密钥后用）
func (s *Server) handleHostKeys(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/hostkeys":
		// 只读接口，和其它读 action 一致：其它方法一律 405。
		// 以前这里不校验方法，DELETE / PUT / PATCH 都会进到处理器里。
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
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
		// 同样是"裸 Decode 没有体积上限"的那一类（审计只点了三处，这是第四处）：
		// 换成 decodeLimit，行为不变（失败仍回 400），但 body 有上限了。
		// 两件事必须分开说：
		//   - 解码失败（体积超限、JSON 坏掉）：如实报那一句，别笼统说成"缺少 target_id"
		//     —— 9MB 的 body 以前会得到 {"error":"缺少 target_id"}，用户照着提示
		//     补字段，怎么补都不对；
		//   - 空 body：decodeLimit 原样返回 io.EOF（允许空 body 的接口靠它识别），
		//     那种情况就是真的没给字段，回"缺少 target_id"。
		if err := decode(r, &body); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if body.TargetID == "" {
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

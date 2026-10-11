package httpapi

import (
	"net/http"
	"strings"
)

// defaultScanLines 是 /api/logs/scan 没给 lines 时扫的尾部行数。
const defaultScanLines = 2000

// lines 的取值范围：下限 1 行、上限 20000 行。
//
// 上限与 service 侧**一致**（internal/service/logscan.go：`lines <= 0 || lines > 20000`
// 就换成 2000）—— 两边口径不一致的话，接口放行 30000 而 service 悄悄按 2000 跑，
// 用户以为扫了三万行（复审·低2 实测的就是这一类静默替换）。
const (
	minScanLines = 1
	maxScanLines = 20000
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
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		files, err := s.Logs.ListLogFiles(targetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, files)

	case "scan":
		// 扫描会往 scan_events 写事件，属于写操作，限 POST
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// lines 解析失败要如实回 400：以前用 fmt.Sscanf 且不判返回值，
		// `lines=abc` 会静默落回默认值，用户以为自己设了别的行数。
		// 与 /api/threat/stats 的 days 同一套判据（都用 queryInt）。
		lines, err := queryIntRange(r.URL.Query(), "lines", defaultScanLines, minScanLines, maxScanLines)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		// 把请求的 context 一路传下去：整次扫描有 20 秒时间预算，
		// 用户关页面/切走时后端提前收手（结果会标 Truncated，不是丢掉）。
		res, err := s.Logs.ScanLog(r.Context(), targetID, r.URL.Query().Get("path"), lines, r.URL.Query().Get("kind"))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		// res 是 logscan.Result，Truncated / TruncatedReason / StoppedAtLine /
		// DroppedHits 四个字段随它一起出去，前端据此提示"结果不完整"。
		writeJSON(w, http.StatusOK, res)

	default:
		http.NotFound(w, r)
	}
}

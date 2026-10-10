package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/guaidao2/awdshell/internal/service"
)

// handleSystem 处理 /api/system/*：本机系统能力，与目标主机无关。
//
// 目前只有"选一个目录"——设置页用它挑默认下载目录。
// 浏览器形态没有这个能力（没有原生对话框），接口会如实报错，让用户手填。
func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/system/")

	switch action {
	case "pick-dir":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if s.PickDir == nil {
			writeErr(w, http.StatusNotImplemented,
				errText("当前形态不支持系统目录选择（浏览器模式下手动填写路径）"))
			return
		}
		dir, err := s.PickDir()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		// 用户取消时回空串，前端据此什么都不做
		writeJSON(w, http.StatusOK, map[string]any{"dir": dir})

	case "save-file":
		// 前端生成的内容（HTML 报告、CSV）统一走这里落到默认下载目录。
		// 没配目录时前端会退回浏览器下载，不会调到这里。
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		}
		// 导出内容可能很大（日志检测 CSV 导的是全部命中行，几万条就够到 8MB），
		// 所以这里用更宽的上限。
		// 空 body 不算 JSON 错误（否则用户看到的是 Go 的 "EOF" 原文），
		// 但导出**必须**有文件名：空 body 顶着一个默认名往下载目录里写一个
		// 空文件，那不是用户要的结果，按"缺字段"如实报更清楚。
		if err := decodeLimit(r, &in, maxExportBytes); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if strings.TrimSpace(in.Name) == "" {
			writeErr(w, http.StatusBadRequest, errText("缺少 name（导出文件名）"))
			return
		}
		// 目录**只**从设置取，不接受请求体指定：
		// 那等于给控制面加一个"往本机任意路径写文件"的原语，而前端没有这个需求。
		dir := ""
		if s.Settings != nil {
			dir = s.Settings.Get().DownloadDir
		}
		if dir == "" {
			writeErr(w, http.StatusBadRequest, errText("没有配置默认下载目录"))
			return
		}
		saved, err := service.SaveTextToDir(dir, in.Name, in.Content)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "saved_to": saved})

	default:
		http.NotFound(w, r)
	}
}

package httpapi

import (
	"io"
	"log"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/guaidao2/awdshell/internal/service"
)

// fileRoutes 处理 /api/files/ 下的所有文件操作。
func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/files/")
	q := r.URL.Query()
	targetID := q.Get("target_id")

	switch action {
	case "list":
		if targetID == "" {
			writeErr(w, http.StatusBadRequest, errText("缺少 target_id"))
			return
		}
		list, err := s.Files.List(targetID, q.Get("path"))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, list)

	case "home":
		home, err := s.Files.Home(targetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"home": home})

	case "startdir":
		// 有效起始目录：配置的目录不存在时回退到家目录（回退信息一并返回给 UI）。
		info, err := s.Files.ResolveStartDir(targetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, info)

	case "cwd":
		// 探测交互终端当前所在目录（文件面板的"同步终端目录"）。
		p, err := s.Files.TermCwd(targetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"path": p})

	case "read":
		content, err := s.Files.ReadText(targetID, q.Get("path"), service.TextMaxBytes)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"content": content})

	case "write":
		var in struct {
			TargetID string `json:"target_id"`
			Path     string `json:"path"`
			Content  string `json:"content"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Files.WriteText(in.TargetID, in.Path, in.Content); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": len(in.Content)})

	case "mkdir":
		var in struct {
			TargetID string `json:"target_id"`
			Path     string `json:"path"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Files.Mkdir(in.TargetID, in.Path); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case "chmod":
		var in struct {
			TargetID string `json:"target_id"`
			Path     string `json:"path"`
			Mode     string `json:"mode"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Files.Chmod(in.TargetID, in.Path, in.Mode); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": in.Mode})

	case "rename":
		var in struct {
			TargetID string `json:"target_id"`
			Old      string `json:"old"`
			New      string `json:"new"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Files.Rename(in.TargetID, in.Old, in.New); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case "delete":
		var in struct {
			TargetID string   `json:"target_id"`
			Paths    []string `json:"paths"`
			Trash    *bool    `json:"trash"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		trash := true // 默认移入回收站，符合"误删代价高"的设计
		if in.Trash != nil {
			trash = *in.Trash
		}
		if err := s.Files.Delete(in.TargetID, in.Paths, trash); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "trashed": trash})

	case "download":
		remotePath := q.Get("path")
		// 先确认读得到、而且是文件，再发响应头 —— 头一旦发出就没法回错误了
		if err := s.Files.EnsureReadableFile(targetID, remotePath); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		name := path.Base(remotePath)
		w.Header().Set("Content-Type", "application/octet-stream")
		// 用 FormatMediaType 组装，并先滤掉控制字符：
		// 直接把文件名拼进头里，遇到 %0a 这种会让 net/http 在校验头值时 panic，
		// 而且这个 panic 发生在响应写出路径上，handler 里的 recover 也救不回。
		w.Header().Set("Content-Disposition",
			mime.FormatMediaType("attachment", map[string]string{"filename": safeFilename(name)}))
		if err := s.Files.Download(targetID, remotePath, w); err != nil {
			log.Printf("下载 %s 失败（响应已开始，无法回错误）: %v", remotePath, err)
			return
		}

	case "upload":
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		// 大文件会被落到系统临时目录，处理完必须清掉，否则越传越占地方
		defer func() {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
		}()
		tid := r.FormValue("target_id")
		dir := r.FormValue("dir")
		file, header, err := r.FormFile("file")
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		defer file.Close()
		dest := path.Join(dir, header.Filename)
		n, err := s.Files.Upload(tid, dest, io.Reader(file))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": dest, "bytes": n, "name": header.Filename})

	default:
		http.NotFound(w, r)
	}
}

type errText string

func (e errText) Error() string { return string(e) }

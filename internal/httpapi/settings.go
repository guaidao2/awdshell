package httpapi

import (
	"errors"
	"io"
	"net/http"

	"github.com/guaidao2/awdshell/internal/service"
)

// settingsResponse 是 POST /api/settings 的响应：**实际生效的设置**
// （扁平字段，与 GET /api/settings 同构，前端现有代码直接读 conn_keep_days 这些
// 字段），外加一个 failed 数组说明这次哪些项没写进去。
//
// 为什么成功路径也要回读值（复审 M4）：逐项写、失败不回滚，库里可能已经是
// "有些新、有些旧"的混合状态。前端里 window.AWD_SETTINGS 只在 200 时更新
// （frontend/dist/settings.js 的 save()），所以响应必须给出**回读到的实际值**；
// 给提交值、或者干脆回 502 让前端保持旧值，用户再点一次保存就会把已经生效的
// 项改回去（界面显示旧值 → 提交旧值 → 覆盖新值）。
type settingsResponse struct {
	service.Settings
	// Failed 列出这次没写进去的设置项 key（全写成功时是空数组）。
	Failed []string `json:"failed"`
}

// handleSettings 读写用户设置。
func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.Settings.Get())

	case http.MethodPost:
		// 用指针字段接收：收到的是**局部更新**，不是整对象替换。
		//
		// 以前直接解成 service.Settings，没出现的字段一律是零值并被写进库：
		// 只发 `{"download_dir":"D:\tmp"}` 会让 conn_keep_days/conn_keep_max/
		// event_keep_days 归 0、trash_on_delete 变 false、term_font_size 被夹到 10
		//（当前设置页碰巧每次都提交全部 8 项，所以没暴露；但接口语义是
		// "整对象替换"，任何只改一项的调用方都会把用户的设置清掉）。
		// 指针能区分"没传"（nil，不动）与"传了零值"（要真的改成 0/false）。
		var in struct {
			ConnKeepDays   *int    `json:"conn_keep_days"`
			ConnKeepMax    *int    `json:"conn_keep_max"`
			EventKeepDays  *int    `json:"event_keep_days"`
			TermFontSize   *int    `json:"term_font_size"`
			TermScrollback *int    `json:"term_scrollback"`
			TrashOnDelete  *bool   `json:"trash_on_delete"`
			TermTrackCwd   *bool   `json:"term_track_cwd"`
			DownloadDir    *string `json:"download_dir"`
		}
		// 空 body 是合法的"一个字都不改"（局部更新语义），不能把 Go 的
		// io.EOF 原文当错误文案回给用户（history/compliance 也是这么处理的）；
		// 除 EOF 以外的解码错仍要如实报（写坏了的 JSON 不能静默当"没传"）。
		if err := decode(r, &in); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		// 先把现有值读出来（Get 已经夹过范围，可以直接作为基线），再逐项覆盖
		cur := s.Settings.Get()
		if in.ConnKeepDays != nil {
			cur.ConnKeepDays = *in.ConnKeepDays
		}
		if in.ConnKeepMax != nil {
			cur.ConnKeepMax = *in.ConnKeepMax
		}
		if in.EventKeepDays != nil {
			cur.EventKeepDays = *in.EventKeepDays
		}
		if in.TermFontSize != nil {
			cur.TermFontSize = *in.TermFontSize
		}
		if in.TermScrollback != nil {
			cur.TermScrollback = *in.TermScrollback
		}
		if in.TrashOnDelete != nil {
			cur.TrashOnDelete = *in.TrashOnDelete
		}
		if in.TermTrackCwd != nil {
			cur.TermTrackCwd = *in.TermTrackCwd
		}
		if in.DownloadDir != nil {
			cur.DownloadDir = *in.DownloadDir
		}
		updated, err := s.Settings.Update(cur)
		if err != nil {
			// 写入是整批一个事务，只有"全成"与"全败"两种，所以这里一律 502。
			// 不能回 200 + 回读值 —— 库这一刻很可能读不出来（锁住/只读/关掉了），
			// Get 会回落成默认值，把默认值当"实际设置"回给前端等于把用户的设置显示丢了。
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, settingsResponse{Settings: updated, Failed: []string{}})

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

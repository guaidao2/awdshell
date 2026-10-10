package service

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/guaidao2/awdshell/internal/store"
)

// Settings 是可持久化的用户设置（存 settings 表，key 统一前缀 app.）。
type Settings struct {
	// 连接历史保留策略；0 表示该条件不启用。
	ConnKeepDays  int `json:"conn_keep_days"`
	ConnKeepMax   int `json:"conn_keep_max"`
	EventKeepDays int `json:"event_keep_days"`
	// 终端显示。
	TermFontSize   int `json:"term_font_size"`
	TermScrollback int `json:"term_scrollback"`
	// 文件删除是否默认移入远程回收站。
	TrashOnDelete bool `json:"trash_on_delete"`
	// 是否让远端 shell 报告当前目录（文件面板可跟随终端目录）。
	TermTrackCwd bool `json:"term_track_cwd"`
	// 默认下载目录：非空时，下载直接把远端文件写到这个目录，
	// 不再交给浏览器（浏览器只会落到系统默认下载目录，选不了地方）。
	// 留空则退回浏览器下载。
	DownloadDir string `json:"download_dir"`
}

// DefaultSettings 返回默认值。
func DefaultSettings() Settings {
	return Settings{
		ConnKeepDays:   90,
		ConnKeepMax:    500,
		EventKeepDays:  30,
		TermFontSize:   14,
		TermScrollback: 10000,
		TrashOnDelete:  true,
		TermTrackCwd:   true,
	}
}

// SettingsService 读写用户设置。
type SettingsService struct {
	store *store.Store
}

// NewSettingsService 构造服务。
func NewSettingsService(st *store.Store) *SettingsService {
	return &SettingsService{store: st}
}

// Get 读取设置（缺项回落到默认值），并**夹取到合法范围**。
//
// 为什么读也要夹：库里的值可能被手工改过或写坏（实测把 app.event_keep_days
// 改成极大值后，main.go 里 `int64(days)*24*3600*1000` 会溢出成负数，
// 于是 PruneComplianceReports(负数) 把**全部**核查报告清掉）。
// 写路径（Update）本来就有 clamp，读路径以前没有。
func (s *SettingsService) Get() Settings {
	d := DefaultSettings()
	connDays := s.intVal("app.conn_keep_days", d.ConnKeepDays)
	connMax := s.intVal("app.conn_keep_max", d.ConnKeepMax)
	eventDays := s.intVal("app.event_keep_days", d.EventKeepDays)
	fontSize := s.intVal("app.term_font_size", d.TermFontSize)
	scrollback := s.intVal("app.term_scrollback", d.TermScrollback)
	return Settings{
		ConnKeepDays:   clamp(connDays, 0, 3650),
		ConnKeepMax:    clamp(connMax, 0, 100000),
		EventKeepDays:  clamp(eventDays, 0, 3650),
		TermFontSize:   clamp(fontSize, 10, 24),
		TermScrollback: clamp(scrollback, 1000, 200000),
		TrashOnDelete:  s.store.GetSetting("app.trash_on_delete", "true") != "false",
		TermTrackCwd:   s.store.GetSetting("app.term_track_cwd", "true") != "false",
		DownloadDir:    strings.TrimSpace(s.store.GetSetting("app.download_dir", "")),
	}
}

// Update 保存设置，并把数值夹取到合法范围后返回实际生效值。
//
// 返回 error：以前 9 处 `_ = s.store.PutSetting` 全吞错，函数也没有 error ——
// 实测库关掉之后调 Update 仍返回一份"看起来已保存"的设置，而 Get 回读还是旧值，
// 用户会以为默认下载目录已经生效。现在任一写入失败都会带回来（值仍然照写，
// 能写的部分不回滚，但调用方知道"这次没全保存成功"）。
func (s *SettingsService) Update(in Settings) (Settings, error) {
	in.ConnKeepDays = clamp(in.ConnKeepDays, 0, 3650)
	in.ConnKeepMax = clamp(in.ConnKeepMax, 0, 100000)
	in.EventKeepDays = clamp(in.EventKeepDays, 0, 3650)
	in.TermFontSize = clamp(in.TermFontSize, 10, 24)
	in.TermScrollback = clamp(in.TermScrollback, 1000, 200000)

	trash := "false"
	if in.TrashOnDelete {
		trash = "true"
	}
	track := "false"
	if in.TermTrackCwd {
		track = "true"
	}
	pairs := []struct{ k, v string }{
		{"app.conn_keep_days", strconv.Itoa(in.ConnKeepDays)},
		{"app.conn_keep_max", strconv.Itoa(in.ConnKeepMax)},
		{"app.event_keep_days", strconv.Itoa(in.EventKeepDays)},
		{"app.term_font_size", strconv.Itoa(in.TermFontSize)},
		{"app.term_scrollback", strconv.Itoa(in.TermScrollback)},
		{"app.trash_on_delete", trash},
		{"app.term_track_cwd", track},
		{"app.download_dir", strings.TrimSpace(in.DownloadDir)},
	}
	var failed []string
	for _, p := range pairs {
		if err := s.store.PutSetting(p.k, p.v); err != nil {
			failed = append(failed, p.k)
		}
	}
	if len(failed) > 0 {
		return in, fmt.Errorf("这些设置项保存失败：%s", strings.Join(failed, "、"))
	}
	return in, nil
}

func (s *SettingsService) intVal(key string, def int) int {
	raw := s.store.GetSetting(key, "")
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

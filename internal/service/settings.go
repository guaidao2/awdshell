package service

import (
	"strconv"

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

// Get 读取设置（缺项回落到默认值）。
func (s *SettingsService) Get() Settings {
	d := DefaultSettings()
	return Settings{
		ConnKeepDays:   s.intVal("app.conn_keep_days", d.ConnKeepDays),
		ConnKeepMax:    s.intVal("app.conn_keep_max", d.ConnKeepMax),
		EventKeepDays:  s.intVal("app.event_keep_days", d.EventKeepDays),
		TermFontSize:   s.intVal("app.term_font_size", d.TermFontSize),
		TermScrollback: s.intVal("app.term_scrollback", d.TermScrollback),
		TrashOnDelete:  s.store.GetSetting("app.trash_on_delete", "true") != "false",
		TermTrackCwd:   s.store.GetSetting("app.term_track_cwd", "true") != "false",
	}
}

// Update 保存设置，并把数值夹取到合法范围后返回实际生效值。
func (s *SettingsService) Update(in Settings) Settings {
	in.ConnKeepDays = clamp(in.ConnKeepDays, 0, 3650)
	in.ConnKeepMax = clamp(in.ConnKeepMax, 0, 100000)
	in.EventKeepDays = clamp(in.EventKeepDays, 0, 3650)
	in.TermFontSize = clamp(in.TermFontSize, 10, 24)
	in.TermScrollback = clamp(in.TermScrollback, 1000, 200000)

	_ = s.store.PutSetting("app.conn_keep_days", strconv.Itoa(in.ConnKeepDays))
	_ = s.store.PutSetting("app.conn_keep_max", strconv.Itoa(in.ConnKeepMax))
	_ = s.store.PutSetting("app.event_keep_days", strconv.Itoa(in.EventKeepDays))
	_ = s.store.PutSetting("app.term_font_size", strconv.Itoa(in.TermFontSize))
	_ = s.store.PutSetting("app.term_scrollback", strconv.Itoa(in.TermScrollback))
	trash := "false"
	if in.TrashOnDelete {
		trash = "true"
	}
	_ = s.store.PutSetting("app.trash_on_delete", trash)
	track := "false"
	if in.TermTrackCwd {
		track = "true"
	}
	_ = s.store.PutSetting("app.term_track_cwd", track)
	return in
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

package service

import (
	"fmt"
	"log"
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
	store SettingsKV
}

// SettingsKV 是设置服务真正需要的存储能力（读一项、整批写）。
//
// 抽成接口不是为了"以后换数据库"，而是为了让**写入失败**这条路径可测：
// 真实 store 是具体类型（*store.Store），没法只让某一项写失败。
//
// PutSettingsKV 是**一个事务写完整批**（store 侧实现保证失败整体回滚），
// 所以现在只有"全成"和"全败"两种结局，不再有半新半旧的中间态。
type SettingsKV interface {
	GetSetting(key, def string) string
	PutSetting(key, value string) error
	PutSettingsKV(pairs [][2]string) error
}

// NewSettingsService 构造服务。
func NewSettingsService(st *store.Store) *SettingsService {
	return &SettingsService{store: st}
}

// NewSettingsServiceWithKV 用任意键值存储构造设置服务（测试注入故障用）。
func NewSettingsServiceWithKV(st SettingsKV) *SettingsService {
	return &SettingsService{store: st}
}

// SettingsWriteError 报告"哪些设置项没写进去"。
//
// 为什么要有类型而不是一句普通 error：控制面要靠它把失败项点名给用户（而不是
// 只给一句"保存失败"）。**整批事务化之后只有"全成"与"全败"两种结局** ——
// 这个类型在失败时 Failed 一定等于全部 key，AllFailed 恒真；保留它是为了
// 让"哪些项"这件事仍然可达，以及测试能断言失败集合。
type SettingsWriteError struct {
	Failed []string // 写失败的设置项 key（按写入顺序）
	Total  int      // 这一次一共尝试写了多少项
}

func (e *SettingsWriteError) Error() string {
	return fmt.Sprintf("这些设置项保存失败：%s", strings.Join(e.Failed, "、"))
}

// AllFailed 报告是不是**一项都没写进去**。
func (e *SettingsWriteError) AllFailed() bool {
	return e.Total > 0 && len(e.Failed) >= e.Total
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

// Update 保存设置，并把数值夹取到合法范围后返回**实际生效的设置**。
//
// 写入走 store.PutSettingsKV —— **整批一个事务**：要么全生效、要么全不生效。
// 以前是 9 次 `_ = s.store.PutSetting`，既吞错又会留下"有些新、有些旧"的中间态，
// 而控制面回 502 时前端只在 200 才更新 window.AWD_SETTINGS，于是界面显示旧值、
// 用户再保存一次就把已经生效的项改回去（复审 M4）。
//
// 返回 error：现在只有"全成"（nil）与"全败"（*SettingsWriteError，Failed 列出
// 全部 key）两种。失败时也照常回读一份实际的 Settings，但调用方应当走 502 ——
// 库这一刻很可能读不出来，Get 会回落成默认值，把默认值当"实际设置"显示出去
// 等于把用户的设置弄丢了。
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
	pairs := [][2]string{
		{"app.conn_keep_days", strconv.Itoa(in.ConnKeepDays)},
		{"app.conn_keep_max", strconv.Itoa(in.ConnKeepMax)},
		{"app.event_keep_days", strconv.Itoa(in.EventKeepDays)},
		{"app.term_font_size", strconv.Itoa(in.TermFontSize)},
		{"app.term_scrollback", strconv.Itoa(in.TermScrollback)},
		{"app.trash_on_delete", trash},
		{"app.term_track_cwd", track},
		{"app.download_dir", strings.TrimSpace(in.DownloadDir)},
	}
	if err := s.store.PutSettingsKV(pairs); err != nil {
		// 原始原因进日志：对外只报"哪些项没保存"，但那句 store 报错
		//（库被锁、磁盘只读…）是排查时唯一有用的线索，不能丢。
		log.Printf("保存设置失败（整批已回滚）: %v", err)
		failed := make([]string, 0, len(pairs))
		for _, p := range pairs {
			failed = append(failed, p[0])
		}
		return s.Get(), &SettingsWriteError{Failed: failed, Total: len(pairs)}
	}
	return s.Get(), nil
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

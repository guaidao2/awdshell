package service

import (
	"errors"
	"strings"
	"testing"
)

// 本文件钉的是复审 M4 的 service 侧那一半。
//
// 最终修法是**整批一个事务**（`store.PutSettingsKV`）：要么全生效、要么全不生效，
// 不存在"写进去一半"的状态 —— 那正是 M4 的根源（前端只在 200 时更新
// window.AWD_SETTINGS，回 502 时界面显示旧值，用户下次保存又把已生效的项改回去）。
//
// 为什么还要替身存储：真实 store 是具体类型（*store.Store），没法让写入失败；
// 而"失败时必须老实报错、不能回一份看起来已保存的设置"这条得能测。

// faultyKV 是一个"整批写不进去"的设置存储。
//
// 写入走一个事务，所以失败是**全批**失败（这正是真 store 的语义）。
type faultyKV struct {
	values map[string]string
	fail   bool // true = 下一次 PutSettingsKV 整批失败
}

func newFaultyKV() *faultyKV { return &faultyKV{values: map[string]string{}} }

func (k *faultyKV) GetSetting(key, def string) string {
	if v, ok := k.values[key]; ok {
		return v
	}
	return def
}

func (k *faultyKV) PutSetting(key, value string) error {
	if k.fail {
		return errors.New("探针：写不进去")
	}
	k.values[key] = value
	return nil
}

// PutSettingsKV 模拟真 store 的事务：失败时**前面的也不生效**。
func (k *faultyKV) PutSettingsKV(pairs [][2]string) error {
	if k.fail {
		return errors.New("探针：整批写不进去")
	}
	for _, p := range pairs {
		k.values[p[0]] = p[1]
	}
	return nil
}

// 成功路径：Update 回的是**回读出来的实际生效值**，不是入参。
//
// 改回错误版本会红：旧实现 `return in` —— 越界值被原样回给前端（界面显示 999，
// 库里其实是夹取后的 24），用户看到的现状是假的。
func TestSettingsUpdateReturnsEffectiveValues(t *testing.T) {
	kv := newFaultyKV()
	svc := NewSettingsServiceWithKV(kv)

	seed := DefaultSettings()
	seed.ConnKeepDays = 30
	seed.DownloadDir = `D:\old`
	got, err := svc.Update(seed)
	if err != nil {
		t.Fatalf("全部可写时不该报错: %v", err)
	}
	if got.DownloadDir != `D:\old` || got.ConnKeepDays != 30 {
		t.Fatalf("成功路径要回实际生效值，得到 %+v", got)
	}
	if again := svc.Get(); again != got {
		t.Errorf("Update 的返回值应与回读一致：返回 %+v，回读 %+v", got, again)
	}
}

// 整批失败：必须报 *SettingsWriteError、AllFailed 为真，而且**库里一个字没变**。
//
// 改回错误版本会红：更早的版本吞掉 PutSetting 的错误、直接返回一份"已保存"的设置，
// 用户以为默认下载目录生效了，Get 回读还是旧值；半事务化的版本还会留下
// "前几项生效、后几项没生效"的混合态。
func TestSettingsUpdateOnBatchFailureChangesNothing(t *testing.T) {
	kv := newFaultyKV()
	svc := NewSettingsServiceWithKV(kv)

	seed := DefaultSettings()
	seed.DownloadDir = `D:\old`
	seed.ConnKeepDays = 30
	if _, err := svc.Update(seed); err != nil {
		t.Fatalf("写种子设置失败: %v", err)
	}
	before := svc.Get()

	kv.fail = true
	in := before
	in.DownloadDir = `D:\new`
	in.ConnKeepDays = 7

	_, err := svc.Update(in)
	var werr *SettingsWriteError
	if !errors.As(err, &werr) {
		t.Fatalf("保存失败要返回 *SettingsWriteError，得到 %v", err)
	}
	if !werr.AllFailed() {
		t.Errorf("整批事务失败时 AllFailed 必须为 true，得到 failed=%v total=%d", werr.Failed, werr.Total)
	}
	if len(werr.Failed) != werr.Total {
		t.Errorf("失败时 Failed 应当列出全部 key：failed=%d total=%d", len(werr.Failed), werr.Total)
	}
	// 事务语义：一项都不该落进库里
	if after := svc.Get(); after != before {
		t.Errorf("整批失败后库里的设置不该有任何变化：之前 %+v，之后 %+v", before, after)
	}
	if kv.values["app.download_dir"] != `D:\old` || kv.values["app.conn_keep_days"] != "30" {
		t.Errorf("库里被写进去了：download_dir=%q conn_keep_days=%q",
			kv.values["app.download_dir"], kv.values["app.conn_keep_days"])
	}

	// 故障排除后同一批必须能写进去（别把失败状态粘住）
	kv.fail = false
	if _, err := svc.Update(in); err != nil {
		t.Fatalf("故障排除后应当写入成功: %v", err)
	}
	if got := svc.Get().DownloadDir; got != `D:\new` {
		t.Errorf("故障排除后应当生效，得到 %q", got)
	}
}

// 真库上的那半边：库关掉之后 Update 仍要老实报错，错误类型能被子类认出来。
func TestSettingsUpdateOnClosedStoreReportsFailure(t *testing.T) {
	base := mkTempDir(t, ".test-settings-closed-")
	st := openStore(t, base)

	svc := NewSettingsService(st)
	if _, err := svc.Update(DefaultSettings()); err != nil {
		t.Fatalf("写种子设置失败: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("关库失败: %v", err)
	}

	_, err := svc.Update(DefaultSettings())
	if err == nil {
		t.Fatal("库已经关掉时 Update 必须报错，不能返回一份「看起来已保存」的设置")
	}
	var werr *SettingsWriteError
	if !errors.As(err, &werr) {
		t.Fatalf("保存失败要返回 *SettingsWriteError，得到 %v", err)
	}
	if !werr.AllFailed() {
		t.Errorf("库关掉时八项都写不进去，AllFailed 应为 true，得到 failed=%v total=%d",
			werr.Failed, werr.Total)
	}
	if !strings.Contains(err.Error(), "保存失败") {
		t.Errorf("文案要能直接给用户看，得到 %q", err.Error())
	}
}

// 真库上的正常路径：Update 回的就是 Get 回读的值（含范围夹取），而且真的落库了。
func TestSettingsUpdateReturnsClampedValues(t *testing.T) {
	base := mkTempDir(t, ".test-settings-clamp-")
	st := openStore(t, base)
	svc := NewSettingsService(st)

	in := DefaultSettings()
	in.TermFontSize = 999
	in.TermScrollback = 1
	in.ConnKeepDays = -5

	eff, err := svc.Update(in)
	if err != nil {
		t.Fatalf("Update 不该报错: %v", err)
	}
	if eff.TermFontSize != 24 {
		t.Errorf("越界的字号应回夹取后的 24，得到 %d", eff.TermFontSize)
	}
	if eff.TermScrollback != 1000 {
		t.Errorf("越界的回滚行数应回夹取后的 1000，得到 %d", eff.TermScrollback)
	}
	if eff.ConnKeepDays != 0 {
		t.Errorf("负的保留天数应夹到 0，得到 %d", eff.ConnKeepDays)
	}
	if got := svc.Get(); got != eff {
		t.Errorf("返回值应与回读一致：返回 %+v，回读 %+v", eff, got)
	}
}

// 事务确实落库了（不是只改了内存）：换一个 Store 实例打开同一个库，值还在。
//
// 改回错误版本会红：只把值留在 faultyKV 的内存里、没走 PutSettingsKV 的实现会过不了这条。
func TestSettingsUpdatePersistsThroughTransaction(t *testing.T) {
	base := mkTempDir(t, ".test-settings-persist-")
	st := openStore(t, base)
	svc := NewSettingsService(st)

	in := DefaultSettings()
	in.ConnKeepDays = 42
	in.DownloadDir = `D:\dl-persist`
	if _, err := svc.Update(in); err != nil {
		t.Fatalf("Update 不该报错: %v", err)
	}
	// 直接从库里读原始 key，不经过 service 的夹取/默认值回落
	if got := st.GetSetting("app.conn_keep_days", ""); got != "42" {
		t.Errorf("app.conn_keep_days 应当落库为 42，得到 %q", got)
	}
	if got := st.GetSetting("app.download_dir", ""); got != `D:\dl-persist` {
		t.Errorf("app.download_dir 应当落库，得到 %q", got)
	}
}

// 写入的 key 名不能被改名（设置页与 main.go 都按这些名字读写）。
func TestSettingsKeysAreStable(t *testing.T) {
	kv := newFaultyKV()
	svc := NewSettingsServiceWithKV(kv)
	if _, err := svc.Update(DefaultSettings()); err != nil {
		t.Fatalf("Update 不该报错: %v", err)
	}
	for _, k := range []string{
		"app.conn_keep_days", "app.conn_keep_max", "app.event_keep_days",
		"app.term_font_size", "app.term_scrollback", "app.trash_on_delete",
		"app.term_track_cwd", "app.download_dir",
	} {
		if _, ok := kv.values[k]; !ok {
			t.Errorf("设置项 %s 没有被写入", k)
		}
	}
	// 目录类值两侧空白要修掉（用户从对话框复制粘贴时常带空格）
	in := DefaultSettings()
	in.DownloadDir = "  D:\\dl  "
	if _, err := svc.Update(in); err != nil {
		t.Fatal(err)
	}
	if got := svc.Get().DownloadDir; got != `D:\dl` {
		t.Errorf("下载目录应去掉首尾空白，得到 %q", got)
	}
}

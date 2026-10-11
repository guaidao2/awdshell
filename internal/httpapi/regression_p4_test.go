package httpapi

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guaidao2/awdshell/internal/service"
	"github.com/guaidao2/awdshell/internal/store"
)

// 本文件钉的是只读复审（第二轮修复之后）剩下的这两条：
//
//	低5 静态资源：**真实存在的文件**加尾斜杠仍回 200（`/app.js/` → 200 + 正文 51443 字节）
//	M4  设置的部分写入：逐项写、失败不回滚，却回 502 —— 界面显示旧值，
//	    下次保存又把已经生效的项改回去
//
// 每条都写成"改回错误版本会红"的形式。

// 低5：真实文件加尾斜杠必须 404。
//
// 以前这条判据整块被跳过：`file` 已经被"文件存在"那个分支设成了合法文件名，
// 下面 `if file == ""` 里的扩展名检查根本不执行，而 `strings.TrimSuffix(p,"/")`
// 的兜底又只看 `p` 不看 `file` —— 于是 `GET /app.js/` 回 200 + app.js 正文
// （复审实测 51443 字节 = 磁盘上 app.js 的真实大小）。旧的回归用例用的是
// `/foo.js/` 这种**不存在**的文件，正好绕开了这个洞。
//
// 改回错误版本会红：/app.js/ 与 /index.html/ 会拿到 200 + 文件正文。
func TestRealStaticFileWithTrailingSlashIsNotFound(t *testing.T) {
	// 用**磁盘上真实存在**的 frontend/dist：os.DirFS 与 embed.FS 的 Stat 语义
	// 一致，而这里的断言要绑在"文件真的存在"上。
	assets := os.DirFS(filepath.Join("..", "..", "frontend", "dist"))
	h := New(Deps{APIToken: "secret", Assets: assets}).Handler()

	// 先把"这些文件确实存在"钉住：否则 404 可能只是"文件本来就缺"
	for _, p := range []string{"/app.js", "/index.html", "/style.css"} {
		w := doGet(t, h, p, "")
		if w.Code != http.StatusOK {
			t.Fatalf("前提不成立：GET %s 应 200（它是磁盘上真实存在的文件），得到 %d", p, w.Code)
		}
		if len(w.Body.Bytes()) == 0 {
			t.Fatalf("前提不成立：GET %s 的正文是空的", p)
		}
	}
	// 真实大小对照：/app.js/ 若又回 200，正文长度会与它一致（复审实测）
	okBody := doGet(t, h, "/app.js", "").Body.Bytes()

	for _, p := range []string{"/app.js/", "/index.html/", "/style.css/", "/settings.js//", "/app.js///"} {
		w := doGet(t, h, p, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s（真实文件加尾斜杠）应 404，得到 %d（正文长度 %d，真身长度 %d）",
				p, w.Code, len(w.Body.Bytes()), len(okBody))
			continue
		}
		if len(w.Body.Bytes()) == len(okBody) && len(okBody) > 0 {
			t.Errorf("GET %s 的正文长度与真实文件相同（%d 字节）—— 正文被发出去了", p, len(w.Body.Bytes()))
		}
		if strings.Contains(string(w.Body.Bytes()), "AWD") {
			t.Errorf("GET %s 的 404 正文里不该有脚本内容", p)
		}
	}

	// 目录语义不能被这条判据带坏：/vendor/ 是目录（没有 index.html），
	// 按原语义走 SPA 回退（前端路由），不是 404。
	if w := doGet(t, h, "/vendor/", ""); w.Code != http.StatusOK {
		t.Errorf("GET /vendor/（真实目录）应仍走 SPA 回退 200，得到 %d", w.Code)
	}
	// -web 首页不受影响
	for _, p := range []string{"/", "/index.html"} {
		w := doGet(t, h, p, "")
		if w.Code != http.StatusOK || !strings.Contains(strings.ToLower(string(w.Body.Bytes())), "<html") {
			t.Errorf("GET %s 应 200 + index.html，得到 %d", p, w.Code)
		}
	}
	// 前端路由（无扩展名、也不是文件）照旧回退
	if w := doGet(t, h, "/settings", ""); w.Code != http.StatusOK {
		t.Errorf("GET /settings（前端路由）应 200 + index.html，得到 %d", w.Code)
	}
}

// 低5（同一条判据的合成样例）：带 index.html 的目录仍要正常发那一份，
// 而子目录里的真实文件加尾斜杠同样 404。
func TestStaticTrailingSlashOnSubdirFile(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":          &fstest.MapFile{Data: []byte("<html>spa</html>")},
		"sub/index.html":      &fstest.MapFile{Data: []byte("<html>sub</html>")},
		"sub/page.js":         &fstest.MapFile{Data: []byte("console.log(2)")},
		"vendor/xterm.min.js": &fstest.MapFile{Data: []byte("//x")},
	}
	h := New(Deps{APIToken: "secret", Assets: assets}).Handler()

	// 真实文件 + 尾斜杠：一律 404
	for _, p := range []string{"/sub/page.js/", "/vendor/xterm.min.js/", "/index.html/"} {
		if w := doGet(t, h, p, ""); w.Code != http.StatusNotFound {
			t.Errorf("GET %s 应 404，得到 %d（正文 %q）", p, w.Code, w.Body.String())
		}
	}
	// 正常形态照旧
	if w := doGet(t, h, "/sub/page.js", ""); w.Code != http.StatusOK {
		t.Errorf("GET /sub/page.js 应 200，得到 %d", w.Code)
	}
	if w := doGet(t, h, "/sub/", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "sub") {
		t.Errorf("GET /sub/ 应 200 + sub/index.html，得到 %d：%q", w.Code, w.Body.String())
	}
}

// faultyKV 是一个"整批写不进去"的设置存储。
//
// 为什么需要替身：真实 store 是具体类型（*store.Store），没法让写入失败。
// 最终修法把写入做成了**整批一个事务**（store.PutSettingsKV），所以失败是全批失败 ——
// 不存在"写进去一半"的状态了，替身也按这个语义来。
type faultyKV struct {
	values map[string]string
	failOn map[string]bool
}

func newFaultyKV() *faultyKV {
	return &faultyKV{values: map[string]string{}, failOn: map[string]bool{}}
}

func (k *faultyKV) GetSetting(key, def string) string {
	if v, ok := k.values[key]; ok {
		return v
	}
	return def
}

func (k *faultyKV) PutSetting(key, value string) error {
	if k.failOn[key] {
		return errors.New("探针：这一项写不进去")
	}
	k.values[key] = value
	return nil
}

// PutSettingsKV 模拟真 store 的事务：任一项失败就整批不生效。
func (k *faultyKV) PutSettingsKV(pairs [][2]string) error {
	for _, p := range pairs {
		if k.failOn[p[0]] {
			return errors.New("探针：整批写不进去")
		}
	}
	for _, p := range pairs {
		k.values[p[0]] = p[1]
	}
	return nil
}

// M4：写入是**整批一个事务**，所以只有两种结局 ——
// 全成（200 + 实际生效值 + failed 空数组）与全败（502）。
//
// 为什么写成一个事务而不是"逐项写、部分成功回 200 + 实际值"：
// frontend/dist/settings.js 的 save() 只在 200 时把响应写回 window.AWD_SETTINGS，
// 而"有些新、有些旧"的混合态会让界面与库长期不一致（用户再点一次保存就把
// 已经生效的项改回去）。全成或全败就没有这个中间态。
//
// 改回错误版本会红：整批失败时若还回 200 + 回读值，前端会把默认值/旧值当成
// 现状显示（库里其实什么都没写进去）。
func TestSettingsWriteIsAllOrNothing(t *testing.T) {
	kv := newFaultyKV()
	settings := service.NewSettingsServiceWithKV(kv)

	// 种子：全部写成功，确认基线
	seed := service.DefaultSettings()
	seed.ConnKeepDays = 30
	seed.DownloadDir = `D:\old`
	if _, err := settings.Update(seed); err != nil {
		t.Fatalf("写种子设置失败: %v", err)
	}

	// 只让 download_dir 一项"写不进去" —— 事务语义下整批都不生效
	kv.failOn["app.download_dir"] = true

	h := New(Deps{APIToken: "secret", Settings: settings}).Handler()
	w := doPost(t, h, "/api/settings", "secret",
		`{"conn_keep_days":7,"download_dir":"D:\\new"}`)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("整批写入失败应回 502，得到 %d：%s", w.Code, w.Body.String())
	}
	// 事务语义：写成功的那一项也不能生效
	if eff := settings.Get(); eff.ConnKeepDays != 30 || eff.DownloadDir != `D:\old` {
		t.Errorf("整批失败后库里不该有任何变化，实际 conn_keep_days=%d download_dir=%q",
			eff.ConnKeepDays, eff.DownloadDir)
	}

	// 全部写成功时：200 + 实际生效值 + failed 是空数组（前端的判断不能靠字段缺失）
	kv.failOn = map[string]bool{}
	w = doPost(t, h, "/api/settings", "secret", `{"conn_keep_days":9}`)
	if w.Code != http.StatusOK {
		t.Fatalf("全部写成功应 200，得到 %d：%s", w.Code, w.Body.String())
	}
	var okOut struct {
		ConnKeepDays int      `json:"conn_keep_days"`
		Failed       []string `json:"failed"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &okOut); err != nil {
		t.Fatalf("解析成功响应失败: %v", err)
	}
	if okOut.ConnKeepDays != 9 {
		t.Errorf("成功响应要回实际生效值 9，得到 %d", okOut.ConnKeepDays)
	}
	if len(okOut.Failed) != 0 {
		t.Errorf("全部写成功时 failed 应为空，得到 %v", okOut.Failed)
	}
	// 响应里的值必须与回读一致（前端拿它当现状）
	eff := settings.Get()
	if eff.ConnKeepDays != okOut.ConnKeepDays {
		t.Errorf("响应与回读不一致：响应 %d，回读 %d", okOut.ConnKeepDays, eff.ConnKeepDays)
	}
}

// M4（另一半）：**一项都没写进去**时仍然是 502。
//
// 理由：库里没有混合状态，而且这一刻回读也不可信（库读不出来时
// SettingsService.Get 会回落成默认值）—— 把默认值当"实际设置"回给前端，
// 等于把用户的设置显示丢了。旧行为在这里是对的，别被上一条改动带跑。
func TestSettingsTotalFailureStillBadGateway(t *testing.T) {
	base, err := os.MkdirTemp(".", ".test-httpapi-settings-all-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	st, err := store.Open(filepath.Join(base, "t.db"))
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	settings := service.NewSettingsService(st)
	if _, err := settings.Update(service.DefaultSettings()); err != nil {
		t.Fatalf("写种子设置失败: %v", err)
	}
	h := New(Deps{APIToken: "secret", Settings: settings}).Handler()

	// 把库关掉：8 项全部写不进去
	if err := st.Close(); err != nil {
		t.Fatalf("关库失败: %v", err)
	}
	w := doPost(t, h, "/api/settings", "secret", `{"conn_keep_days":7}`)
	if w.Code != http.StatusBadGateway {
		t.Errorf("一项都没写进去时应回 502（不是 200 + 默认值），得到 %d：%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "保存失败") {
		t.Errorf("失败正文要说清是保存失败，得到 %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "conn_keep_days\":90") {
		t.Errorf("不能把回读到的默认值当成实际设置回给前端：%s", w.Body.String())
	}
}

// 顺带钉住 fs.FS 的语义：这里用到的 os.DirFS 与生产一致（embed.FS 也是 fs.FS），
// 免得以后有人把 Assets 当成"必须是 embed.FS"而改掉判据。
var _ fs.FS = fstest.MapFS{}

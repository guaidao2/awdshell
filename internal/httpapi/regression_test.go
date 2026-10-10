package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guaidao2/awdshell/internal/service"
	"github.com/guaidao2/awdshell/internal/store"
)

// 本文件是这一批控制面修复的回归测试。
//
// 每条都盯一个"能改回去"的错误写法：
//   M1 未规范化的路径在鉴权之前被 ServeMux 307 掉（免费探测端点）
//   M2 /ws/ 用 404/403 区分"会话不存在"与"令牌不对"（存在性 oracle）
//   M3 几处裸 json.Decode 没有体积上限
//   M4 POST /api/settings 是整对象替换（只改一项会把其它项清零）
//   低L2 SPA 回退把缺失的 .js/.css 回成 index.html 200
//
// 用的 service 大多是 nil：判据发生在调用 service 之前，走到 service
// 会因为 nil panic 而被 recover 成 500 —— 那也是"判据失效"的信号。

// 本机来源：httptest 默认 Host 是 example.com，会被 Host/Origin 兜底挡掉，
// 而这几条要测的是"鉴权发生在重定向之前"，必须让请求本身是放行的本机来源。
const testHost = "127.0.0.1:39123"

func doGet(t *testing.T, h http.Handler, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = testHost
	if token != "" {
		req.Header.Set("X-Awd-Token", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func doPost(t *testing.T, h http.Handler, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Host = testHost
	if token != "" {
		req.Header.Set("X-Awd-Token", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// M1：不干净的路径不能在鉴权之前被 307 重定向掉。
//
// 改回错误版本会红：`GET //api/targets` 不带令牌会得到 307（ServeMux 的
// cleanPath 重定向），而不是 403 —— 于是本机任意进程/页面靠 307 与 403
// 的差别就能问出哪些端点存在，一个字节的令牌都不用带。
func TestUncleanPathsAreAuthenticatedBeforeRedirect(t *testing.T) {
	h := newTestServer("secret").Handler()

	unclean := []string{
		"//api/targets",
		"//api/health",
		"/api//targets",
		"/./api/health",
		"/api/../api/health",
	}
	for _, p := range unclean {
		// 不带令牌：一律 403（既不能 307、也不能 301）
		w := doGet(t, h, p, "")
		if w.Code != http.StatusForbidden {
			t.Errorf("GET %s 不带令牌应 403，得到 %d（Location=%q）",
				p, w.Code, w.Header().Get("Location"))
		}
		// 带对令牌：应该被正常服务，而不是退化成一次重定向
		w = doGet(t, h, p, "secret")
		if w.Code == http.StatusTemporaryRedirect || w.Code == http.StatusMovedPermanently {
			t.Errorf("GET %s 带令牌不该回重定向，得到 %d（Location=%q）",
				p, w.Code, w.Header().Get("Location"))
		}
	}

	// 折出来的路径必须真的落到原来的处理器上（health 不依赖任何 service）
	if w := doGet(t, h, "//api/health", "secret"); w.Code != http.StatusOK {
		t.Errorf("GET //api/health 带令牌应 200，得到 %d：%s", w.Code, w.Body.String())
	}
	// 规范化不能把结尾的 "/" 吃掉：/api/targets/ 是"按 id 操作"那条路由
	if got := canonicalPath("/api/targets/"); got != "/api/targets/" {
		t.Errorf("canonicalPath 不该去掉结尾斜杠，得到 %q", got)
	}
}

// M2：/ws/ 不能拿 404 与 403 的差别当"会话是否存在"的探针。
//
// 改回错误版本会红：会话不存在时旧代码回 404（"会话不存在"），
// 只有令牌不对才 403 —— 未带控制面令牌的任何人因此能枚举会话 id。
//
// 注意：这里只能构造"会话不存在"这一侧 —— 造一个真会话要连真实 SSH 目标，
// 单测里做不到。但存在性 oracle 的判据就在 404/403 这一处，锁住它即可。
func TestTerminalWSDeniesWithoutSessionOracle(t *testing.T) {
	s := New(Deps{
		APIToken: "secret",
		// 空会话表：Get 一定找不到
		Sessions: service.NewSessionService(nil, nil, nil),
		Assets:   fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}},
	})
	h := s.Handler()

	for _, p := range []string{
		"/ws/term/does-not-exist",
		"/ws/term/does-not-exist?token=x",
		"/ws/term/",
	} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = testHost
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("GET %s 应 403（不区分会话存在与否），得到 %d：%s",
				p, w.Code, strings.TrimSpace(w.Body.String()))
		}
	}
}

// M3：三处裸 Decode 的接口现在有体积上限。
//
// 改回错误版本会红：旧代码会把整个 9MB body 读进内存，然后因为没有 service
// 而 panic（被 recover 成 500）；现在应该在解码阶段就以 400 结束。
func TestBigBodyIsRejectedBeforeHandler(t *testing.T) {
	h := newTestServer("secret").Handler()
	huge := `{"target_id":"` + strings.Repeat("a", 9<<20) + `"}`
	for _, p := range []string{
		"/api/history",          // server.go 的清空历史
		"/api/compliance/clear", // compliance.go 的清空报告
	} {
		w := doPost(t, h, p, "secret", huge)
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST %s 9MB body 应 400（超上限），得到 %d：%s",
				p, w.Code, strings.TrimSpace(w.Body.String()))
		}
		if !strings.Contains(w.Body.String(), "超过") {
			t.Errorf("POST %s 的报错应说明是体积问题，得到 %s", p, w.Body.String())
		}
	}
	// 允许空 body 的语义不能被这轮改动破坏
	for _, p := range []string{"/api/history", "/api/compliance/clear"} {
		w := doPost(t, h, p, "secret", "")
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST %s 空 body 应 400（缺 target_id），得到 %d", p, w.Code)
		}
	}
}

// M4：POST /api/settings 是**局部更新**，没传的字段必须保持原值。
//
// 改回错误版本会红：旧代码直接把请求体解成 service.Settings，只发
// {"download_dir":...} 会让 conn_keep_days/conn_keep_max/event_keep_days 归 0、
// trash_on_delete 变 false、term_font_size 被夹到 10、term_scrollback 被夹到 1000。
func TestSettingsPartialUpdateKeepsOtherFields(t *testing.T) {
	base, err := os.MkdirTemp(".", ".test-httpapi-settings-")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	st, err := store.Open(filepath.Join(base, "t.db"))
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	settings := service.NewSettingsService(st)
	// 种子值刻意都不是默认值：这样"被保住了"与"碰巧落在默认值上"能区分开
	seed := service.DefaultSettings()
	seed.ConnKeepDays = 7
	seed.ConnKeepMax = 42
	seed.EventKeepDays = 3
	seed.TermFontSize = 18
	seed.TermScrollback = 5000
	seed.TrashOnDelete = true
	seed.TermTrackCwd = true
	if _, err := settings.Update(seed); err != nil {
		t.Fatalf("写种子设置失败: %v", err)
	}

	h := New(Deps{APIToken: "secret", Settings: settings}).Handler()

	// 只提交一项
	w := doPost(t, h, "/api/settings", "secret", `{"download_dir":"D:\\tmp"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/settings 应 200，得到 %d：%s", w.Code, w.Body.String())
	}
	got := settings.Get()
	if got.DownloadDir != `D:\tmp` {
		t.Errorf("download_dir 应被改成 D:\\tmp，得到 %q", got.DownloadDir)
	}
	if got.ConnKeepDays != 7 || got.ConnKeepMax != 42 || got.EventKeepDays != 3 {
		t.Errorf("没传的保留策略被改坏了：days=%d max=%d events=%d（应为 7/42/3）",
			got.ConnKeepDays, got.ConnKeepMax, got.EventKeepDays)
	}
	if got.TermFontSize != 18 || got.TermScrollback != 5000 {
		t.Errorf("没传的终端设置被改坏了：font=%d scrollback=%d（应为 18/5000）",
			got.TermFontSize, got.TermScrollback)
	}
	if !got.TrashOnDelete || !got.TermTrackCwd {
		t.Errorf("没传的开关被改坏了：trash=%v trackcwd=%v（都应为 true）",
			got.TrashOnDelete, got.TermTrackCwd)
	}

	// 反向：显式传零值/ false 必须真的生效（指针要能区分"没传"与"传了零值"）
	w = doPost(t, h, "/api/settings", "secret",
		`{"conn_keep_days":0,"trash_on_delete":false,"term_font_size":12}`)
	if w.Code != http.StatusOK {
		t.Fatalf("第二次 POST 应 200，得到 %d：%s", w.Code, w.Body.String())
	}
	got = settings.Get()
	if got.ConnKeepDays != 0 {
		t.Errorf("显式传 conn_keep_days=0 应真的生效，得到 %d", got.ConnKeepDays)
	}
	if got.TrashOnDelete {
		t.Error("显式传 trash_on_delete=false 应真的生效")
	}
	if got.TermFontSize != 12 {
		t.Errorf("显式传 term_font_size=12 应真的生效，得到 %d", got.TermFontSize)
	}
	if got.EventKeepDays != 3 || got.ConnKeepMax != 42 {
		t.Errorf("这一轮没传的字段仍应保留：events=%d max=%d（应为 3/42）",
			got.EventKeepDays, got.ConnKeepMax)
	}
}

// 低L3：writeErr 不能把 Go 解码器原文、本机绝对路径原样回给前端。
//
// 改回错误版本会红：以前是 `{"error": err.Error()}`，本机库路径会整段透出去，
// 500 的原始细节也照给（用户看不懂，还顺手交出目录结构）。
func TestWriteErrHidesLocalDetails(t *testing.T) {
	send := func(status int, err error) (int, string) {
		w := httptest.NewRecorder()
		writeErr(w, status, err)
		return w.Code, w.Body.String()
	}

	// 本包自己写的文案（errText）本来就是给用户看的，必须照旧透传
	if _, body := send(http.StatusBadRequest, errText("缺少 target_id")); !strings.Contains(body, "缺少 target_id") {
		t.Errorf("errText 文案不该被替换，得到 %s", body)
	}
	// 远端路径保留：用户要靠它定位问题
	if _, body := send(http.StatusBadGateway,
		errors.New("sftp: /var/www/html/x.php: permission denied")); !strings.Contains(body, "/var/www/html/x.php") {
		t.Errorf("远端路径应保留，得到 %s", body)
	}
	// 本机 Windows 绝对路径要遮掉（SQLite/文件类报错最容易带出来）
	if _, body := send(http.StatusBadRequest,
		errors.New(`open D:\awdshell\data\t.db: access is denied`)); strings.Contains(body, `D:\awdshell`) {
		t.Errorf("本机绝对路径不该回给前端，得到 %s", body)
	}
	// 500 只说一句，细节留给日志
	if _, body := send(http.StatusInternalServerError,
		errors.New(`disk I/O error`)); strings.Contains(body, "disk I/O error") {
		t.Errorf("500 的原始细节不该回给前端，得到 %s", body)
	}
}

// 低L2：SPA 回退只服务前端路由，不能把缺失的静态资源回成 index.html 200。
//
// 改回错误版本会红：/missing.js 会拿到 200 + 一段 HTML，浏览器把 HTML 当 JS
// 执行（onload 照样触发），表现成"加载成功但功能没生效"，不报错 ——
// CodeMirror/xterm 的动态加载踩过这个坑。
func TestSPAFallbackDoesNotServeHTMLForMissingAssets(t *testing.T) {
	h := New(Deps{
		APIToken: "secret",
		Assets: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>spa</html>")},
			"app.js":     &fstest.MapFile{Data: []byte("console.log(1)")},
		},
	}).Handler()

	// 存在的资源照常给
	if w := doGet(t, h, "/app.js", ""); w.Code != http.StatusOK {
		t.Errorf("存在的 /app.js 应 200，得到 %d", w.Code)
	}

	for _, p := range []string{"/missing.js", "/vendor/xterm.css", "/app.js.map", "/style.css"} {
		w := doGet(t, h, p, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("缺失的静态资源 %s 应 404，得到 %d", p, w.Code)
		}
		if strings.Contains(w.Body.String(), "<html") {
			t.Errorf("缺失的静态资源 %s 不该回 HTML（正文 %q）", p, w.Body.String())
		}
	}

	// 前端路由（无扩展名）仍要回退到 index.html，别把 SPA 一起弄坏
	w := doGet(t, h, "/settings", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "spa") {
		t.Errorf("前端路由 /settings 应回退到 index.html（200），得到 %d：%q", w.Code, w.Body.String())
	}
}

package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
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

// 本文件钉的是复审报告（.tmp/audit33/review-report.md）里那一批边界：
//
//	低1 本机路径遮蔽遮不全（带空格只遮一半、C:/ 完全不遮、UNC 不遮）
//	低3 缺失静态资源的 404 判据对结尾斜杠失效（/foo.js/ 回 200 + HTML）
//	低4 空 body 与"体积超限"的原因说错（把 io.EOF、把超限说成缺字段）
//	低5 只读 action 非 GET → 405 覆盖不全（compliance / health / recent）
//	低6 上传时迟到的 dir 被静默忽略（文件落到远端根目录，接口还回 200）
//
// 每条都写成"改回错误版本会红"的形式。

// jsonErr 取出 writeErr 写回的 {"error": ...}（正文是 JSON，
// 中文与 < 会被编码，所以不能直接拿 Body 字符串比对）。
func jsonErr(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析错误正文失败: %v（正文 %s）", err, w.Body.String())
	}
	return out.Error
}

// 低1：本机路径必须遮全。
//
// 改回错误版本会红：老正则 `[A-Za-z]:\\[^\s"'<>|]*` 遇空格就停
// （"open C:\Program Files\...\t.db: ..." 会漏出 "Files\...\t.db"），
// 而 C:/ 这种正斜杠写法整段原样回给前端；UNC 也不遮。
func TestWriteErrMasksWholeLocalPath(t *testing.T) {
	cases := []struct{ name, in, leak string }{
		{"带空格的盘符路径", `open C:\Program Files\awdshell\data\t.db: access is denied`, `Files\awdshell`},
		{"正斜杠写法", `open C:/Users/guaidao2/awdshell/t.db: disk I/O error`, `guaidao2`},
		{"UNC 路径", `open \\server\share\secret.db: access is denied`, `share\secret`},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		writeErr(w, http.StatusBadRequest, errors.New(c.in))
		msg := jsonErr(t, w)
		if strings.Contains(msg, c.leak) {
			t.Errorf("%s：本机路径没遮全，用户看到 %q", c.name, msg)
		}
		if !strings.Contains(msg, "<本地路径>") {
			t.Errorf("%s：应遮成 <本地路径>，用户看到 %q", c.name, msg)
		}
	}

	// 反向：远端目标是 Linux，POSIX 路径必须照旧保留（用户要靠它定位问题）
	w := httptest.NewRecorder()
	writeErr(w, http.StatusBadGateway, errors.New("sftp: /var/www/html/x.php: permission denied"))
	if msg := jsonErr(t, w); !strings.Contains(msg, "/var/www/html/x.php") {
		t.Errorf("远端路径不该被遮，用户看到 %q", msg)
	}
}

// 低3：缺失静态资源的 404 判据对结尾斜杠也要成立。
//
// 改回错误版本会红：`path.Ext("foo.js/")` 是空串（最后一个斜杠之后没有点了），
// `/foo.js/` 会落进 SPA 回退，拿到 200 + 一段 HTML —— 浏览器把 HTML 当 JS 执行，
// onload 照样触发、只是功能不生效，正是这条判据要堵的那一类。
func TestSPAFallbackRejectsTrailingSlashAssets(t *testing.T) {
	h := New(Deps{
		APIToken: "secret",
		Assets: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<html>spa</html>")},
			"app.js":     &fstest.MapFile{Data: []byte("console.log(1)")},
		},
	}).Handler()

	for _, p := range []string{"/foo.js/", "/missing.css/", "/vendor/xterm.js/", "/missing.map/"} {
		w := doGet(t, h, p, "")
		if w.Code != http.StatusNotFound {
			t.Errorf("缺失的静态资源 %s 应 404，得到 %d", p, w.Code)
		}
		if strings.Contains(w.Body.String(), "<html") {
			t.Errorf("缺失的静态资源 %s 不该回 HTML（正文 %q）", p, w.Body.String())
		}
	}

	// 反向：前端路由（无扩展名）带结尾斜杠仍要回退 index.html，别把 SPA 弄坏
	w := doGet(t, h, "/settings/", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "spa") {
		t.Errorf("前端路由 /settings/ 应回退到 index.html（200），得到 %d：%q", w.Code, w.Body.String())
	}
}

// 低4-a：空 body 不能把 Go 的 io.EOF 原文当用户文案，坏 JSON 仍要如实报。
//
// 改回错误版本会红：POST /api/settings 与 /api/system/save-file 的空 body
// 会回 {"error":"EOF"}（Go 解码器原文进用户文案），而这两个接口
// （history/compliance 都写了 !errors.Is(err, io.EOF)）没写那条判据。
func TestEmptyBodyDoesNotLeakEOF(t *testing.T) {
	base, err := os.MkdirTemp(".", ".test-httpapi-p3-")
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
	h := New(Deps{APIToken: "secret", Settings: settings}).Handler()

	// 空 body：局部更新的合法输入 —— 一个字都不改，回 200 + 当前设置
	w := doPost(t, h, "/api/settings", "secret", "")
	if w.Code != http.StatusOK {
		// 用 Errorf 而不是 Fatalf：下面 save-file 那一段要一起验
		t.Errorf("POST /api/settings 空 body 应 200（没有字段要改），得到 %d：%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "EOF") {
		t.Errorf("空 body 不该把 io.EOF 原文回给用户：%s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "term_font_size") {
		t.Errorf("应回当前设置，得到 %s", w.Body.String())
	}

	// 坏 JSON 仍要如实报（不能静默当"没传"）
	w = doPost(t, h, "/api/settings", "secret", `{"term_font_size":`)
	if w.Code != http.StatusBadRequest || jsonErr(t, w) == "EOF" {
		t.Errorf("坏 JSON 应 400 + 一句人话，得到 %d：%s", w.Code, w.Body.String())
	}

	// save-file：空 body 以前是 {"error":"EOF"}；现在按"缺字段"说人话
	w = doPost(t, h, "/api/system/save-file", "secret", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST /api/system/save-file 空 body 应 400（没有文件名），得到 %d：%s", w.Code, w.Body.String())
	}
	if msg := jsonErr(t, w); strings.Contains(msg, "EOF") || !strings.Contains(msg, "name") {
		t.Errorf("空 body 的文案应说清是缺文件名而不是 EOF，得到 %q", msg)
	}
	w = doPost(t, h, "/api/system/save-file", "secret", `{"name":"x.txt"`)
	if msg := jsonErr(t, w); w.Code != http.StatusBadRequest || strings.Contains(msg, "EOF") {
		t.Errorf("save-file 坏 JSON 应 400 + 一句人话，得到 %d：%q", w.Code, msg)
	}
}

// 低4-b：hostkey 的"体积超限"与"缺字段"必须分开报。
//
// 改回错误版本会红：POST /api/hostkeys/forget 传 9MB body 会得到
// {"error":"缺少 target_id"} —— 把体积超限说成了缺字段，用户照着提示
// 补 target_id，怎么补都不对。
func TestHostkeyForgetReportsRealReason(t *testing.T) {
	h := newTestServer("secret").Handler()

	huge := `{"target_id":"` + strings.Repeat("a", 9<<20) + `"}`
	w := doPost(t, h, "/api/hostkeys/forget", "secret", huge)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("9MB body 应 400，得到 %d：%s", w.Code, w.Body.String())
	}
	msg := jsonErr(t, w)
	if !strings.Contains(msg, "超过") {
		t.Errorf("超限的文案应说明是体积问题，得到 %q", msg)
	}
	if strings.Contains(msg, "target_id") {
		t.Errorf("体积超限不该说成缺字段，得到 %q", msg)
	}

	// 空 body 才是真的缺字段（允许空 body 的语义不能被这轮改动破坏）
	w = doPost(t, h, "/api/hostkeys/forget", "secret", "")
	if w.Code != http.StatusBadRequest || !strings.Contains(jsonErr(t, w), "target_id") {
		t.Errorf("空 body 应 400 说缺 target_id，得到 %d：%s", w.Code, w.Body.String())
	}

	// 坏 JSON：如实报格式错，别笼统说成缺字段
	w = doPost(t, h, "/api/hostkeys/forget", "secret", `{"target_id":`)
	if w.Code != http.StatusBadRequest || strings.Contains(jsonErr(t, w), "target_id") {
		t.Errorf("坏 JSON 应 400 说格式不对，得到 %d：%s", w.Code, w.Body.String())
	}
}

// 低5：只读 action 用写方法打过来一律 405（compliance 三条 + health/recent）。
//
// 改回错误版本会红：带对令牌的 POST /api/compliance/checks 会 **200**
// （PUT 也 200），POST history/report 同样直接进处理器；
// /api/health 与 /api/recent 以前也完全不看方法。
//
// 这些 service 都是 nil：方法校验发生在调用 service 之前，走到 service
// 会因为 nil panic 被 recover 成 500 —— 那也是"判据失效"的信号。
func TestReadOnlyActionsIncludeComplianceHealthRecent(t *testing.T) {
	h := newTestServer("secret").Handler()
	paths := []string{
		"/api/compliance/checks",
		"/api/compliance/history",
		"/api/compliance/report?id=1",
		"/api/health",
		"/api/recent",
	}
	for _, p := range paths {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			req := httptest.NewRequest(m, p, strings.NewReader("{}"))
			req.Header.Set("X-Awd-Token", "secret")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s 应 405，得到 %d", m, p, w.Code)
			}
		}
	}

	// 反向：GET 仍然要走到处理器（nil service 会 panic→500，而不是 405/403），
	// 也就是"方法校验别把合法读一起挡掉"
	for _, p := range []string{"/api/compliance/checks", "/api/recent"} {
		w := doGet(t, h, p, "secret")
		if w.Code == http.StatusMethodNotAllowed || w.Code == http.StatusForbidden {
			t.Errorf("GET %s 不该被挡，得到 %d", p, w.Code)
		}
	}
}

// 低6：上传时"迟到的 dir"必须 400，不能静默忽略。
//
// 改回错误版本会红：multipart 顺序是 target_id → file → dir 时，file 那一刻
// dir 还是空串，safeRemoteJoin("", "x") 算出 /x，文件被暂存到远端**根目录**，
// 随后读到的 dir 只做长度校验、不再生效，接口照样回 200 说上传成功。
//
// 暂存走的是真 SFTP，单测里用 Server.stageUpload 替身顶上：
// 字段顺序判定发生在暂存**之后**，不替身这一段就没法在不起 SSH 的情况下测到。
func TestUploadLateDirIsRejected(t *testing.T) {
	s := newTestServer("secret")
	staged := false
	s.stageUpload = func(targetID, dest string, r io.Reader) (string, int64, error) {
		staged = true
		n, _ := io.Copy(io.Discard, r)
		// 空 tmp：abort() 见到空串就跳过清理（那一步同样要真 SSH）
		return "", n, nil
	}
	h := s.Handler()

	send := func(fields func(*multipart.Writer)) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fields(mw)
		_ = mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/api/files/upload", &buf)
		req.Header.Set("X-Awd-Token", "secret")
		req.Header.Set("Content-Type", mw.FormDataContentType())
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	// dir 排在 file 之后：必须 400，而且要说明是字段顺序
	w := send(func(mw *multipart.Writer) {
		_ = mw.WriteField("target_id", "t1")
		fw, _ := mw.CreateFormFile("file", "x.txt")
		_, _ = fw.Write([]byte("payload"))
		_ = mw.WriteField("dir", "/tmp")
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("file 之后才给 dir 应 400，得到 %d：%s", w.Code, w.Body.String())
	}
	if msg := jsonErr(t, w); !strings.Contains(msg, "dir") {
		t.Errorf("文案要说清是 dir 的顺序问题，得到 %q", msg)
	}
	if !staged {
		t.Error("这条用例的前提是「文件已按空 dir 暂存」，没暂存就测不到那个场景")
	}

	// 反向：dir 排在 file 之前不能被误伤。
	// 这里没有真 SFTP，正确顺序最终会停在 CommitUpload（nil service → panic → 500），
	// 所以只断言"没被判成字段顺序错"。
	w = send(func(mw *multipart.Writer) {
		_ = mw.WriteField("dir", "/tmp")
		_ = mw.WriteField("target_id", "t1")
		fw, _ := mw.CreateFormFile("file", "x.txt")
		_, _ = fw.Write([]byte("payload"))
	})
	if w.Code == http.StatusBadRequest {
		t.Errorf("dir 排在 file 之前不该被判成字段顺序错，得到 %d：%s", w.Code, w.Body.String())
	}
}

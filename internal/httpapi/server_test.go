package httpapi

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guaidao2/awdshell/internal/service"
	"github.com/guaidao2/awdshell/internal/store"
)

// 这个文件盯的是两件曾经真出过事的事：
//
//  1. 控制面令牌必须覆盖**所有** /api/ 请求。曾经只对"非 GET"强制，
//     于是裸 GET 能触发写路径（Go 的 GET 也能带 body），而 Host/Origin 兜底
//     对本机来源一律放行 —— 等于没有边界。
//  2. 每个会改数据的 action 必须拒绝错误的方法。
//
// 这些 service 都传 nil：方法校验与令牌检查都发生在调用 service 之前，
// 走到 service 就说明判据失效了（那时测试会因为 nil panic 而失败，也是信号）。

func newTestServer(token string) *Server {
	return New(Deps{
		APIToken: token,
		Assets:   fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}},
		Version:  "test",
	})
}

// 请求体里的 dir 必须被忽略。
//
// 那是个"往本机任意路径写文件"的原语（还会顺手 MkdirAll 建目录），
// 而前端从来不传它 —— 谁把它加回来，这条测试就该红。
func TestSaveFileIgnoresClientDir(t *testing.T) {
	base, err := os.MkdirTemp(".", ".test-httpapi-")
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
	dl := filepath.Join(base, "downloads")
	cfg := service.DefaultSettings()
	cfg.DownloadDir = dl
	_, _ = settings.Update(cfg)

	s := New(Deps{
		APIToken: "secret",
		Settings: settings,
		Assets:   fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}},
	})

	evil := filepath.Join(base, "evil")
	body := `{"name":"x.txt","content":"hi","dir":` + strconv.Quote(evil) + `}`
	req := httptest.NewRequest(http.MethodPost, "/api/system/save-file", strings.NewReader(body))
	req.Header.Set("X-Awd-Token", "secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("保存应成功，得到 %d：%s", w.Code, w.Body.String())
	}
	var resp struct {
		SavedTo string `json:"saved_to"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if !strings.HasPrefix(resp.SavedTo, dl) {
		t.Errorf("应落在配置的下载目录 %q，实际 %q", dl, resp.SavedTo)
	}
	if _, err := os.Stat(evil); err == nil {
		t.Errorf("请求体指定的目录不该被创建: %s", evil)
	}
}

// decodeLimit 的边界：正好等于上限要放行，多一个字节就要报"超过"。
//
// 曾经的写法只看 Decode 的返回值，于是"多出一个字节但 JSON 仍完整"会被放行。
func TestDecodeLimitBoundary(t *testing.T) {
	const limit = 100
	prefix := `{"content":"`
	suffix := `"}`
	overhead := len(prefix) + len(suffix)

	mkBody := func(total int) string {
		return prefix + strings.Repeat("a", total-overhead) + suffix
	}
	post := func(body string) error {
		var v struct {
			Content string `json:"content"`
		}
		return decodeLimit(httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body)), &v, limit)
	}

	if err := post(mkBody(limit)); err != nil {
		t.Errorf("正好 %d 字节应放行，得到: %v", limit, err)
	}
	err := post(mkBody(limit + 1))
	if err == nil {
		t.Errorf("超过上限 1 字节应被拒")
	} else if !strings.Contains(err.Error(), "超过") {
		t.Errorf("超限错误文案应说明是体积问题，得到: %v", err)
	}
	if err := post(mkBody(limit + 500)); err == nil {
		t.Errorf("明显超限应被拒")
	}
}

// 上传的协议层校验。
//
// 这几条都在调用 SFTP 之前就返回，所以不需要真目标机：
// 字段顺序、缺文件、多文件、非 multipart —— 正是上一版没有测试覆盖的地方
// （流式上传是本批最危险的新代码）。
func TestUploadProtocolErrors(t *testing.T) {
	h := newTestServer("secret").Handler()

	send := func(contentType string, body func(*multipart.Writer)) int {
		var buf bytes.Buffer
		if body != nil {
			mw := multipart.NewWriter(&buf)
			body(mw)
			_ = mw.Close()
			contentType = mw.FormDataContentType()
		}
		req := httptest.NewRequest(http.MethodPost, "/api/files/upload", &buf)
		req.Header.Set("X-Awd-Token", "secret")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	// 不是 multipart
	if code := send("application/json", nil); code != http.StatusBadRequest {
		t.Errorf("非 multipart 应 400，得到 %d", code)
	}
	// 声明 multipart 却没有 boundary
	if code := send("multipart/form-data", nil); code != http.StatusBadRequest {
		t.Errorf("缺 boundary 应 400，得到 %d", code)
	}
	// 只有字段、没有 file part
	if code := send("", func(mw *multipart.Writer) {
		_ = mw.WriteField("target_id", "t1")
		_ = mw.WriteField("dir", "/tmp")
	}); code != http.StatusBadRequest {
		t.Errorf("没有 file part 应 400，得到 %d", code)
	}
	// file 出现在 target_id 之前：必须明确报错，不能静默丢文件
	if code := send("", func(mw *multipart.Writer) {
		fw, _ := mw.CreateFormFile("file", "a.txt")
		_, _ = fw.Write([]byte("x"))
		_ = mw.WriteField("target_id", "t1")
	}); code != http.StatusBadRequest {
		t.Errorf("字段顺序不对应 400，得到 %d", code)
	}
	// 缺 target_id
	if code := send("", func(mw *multipart.Writer) {
		_ = mw.WriteField("dir", "/tmp")
		fw, _ := mw.CreateFormFile("file", "a.txt")
		_, _ = fw.Write([]byte("x"))
	}); code != http.StatusBadRequest {
		t.Errorf("缺 target_id 应 400，得到 %d", code)
	}
}

// 远端路径不能靠 .. 跑到目标目录之外。
func TestSafeRemoteJoin(t *testing.T) {
	ok := []struct{ dir, name, want string }{
		{"/tmp", "a.txt", "/tmp/a.txt"},
		{"/var/www/html", "index.php", "/var/www/html/index.php"},
		{"/tmp/", "sub/b.txt", "/tmp/sub/b.txt"},
		// 根目录：base 是 "/" 时不能拼出 "//"（那会让任何路径都不满足前缀，
		// 用户在文件面板切到 `/` 之后上传必失败，还报一句误导人的话）
		{"/", "atroot.txt", "/atroot.txt"},
		{"", "atroot2.txt", "/atroot2.txt"},
		{"/", "a/b.txt", "/a/b.txt"},
	}
	for _, c := range ok {
		got, err := safeRemoteJoin(c.dir, c.name)
		if err != nil {
			t.Errorf("safeRemoteJoin(%q,%q) 不该失败: %v", c.dir, c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("safeRemoteJoin(%q,%q) = %q，期望 %q", c.dir, c.name, got, c.want)
		}
	}
	bad := []struct{ dir, name string }{
		{"/tmp", "../../etc/passwd"},
		{"/tmp", "../x"},
		{"/var/www", "../../../../etc/shadow"},
		{"/tmp", ".."},
		// **目录里的 .. 必须直接拒**：以前是先 Clean("/"+dir) 再用折出来的 base
		// 做前缀校验，于是 dir="/tmp/.." 折成 "/" 之后任何绝对路径都通过
		//（实测曾能写到 /etc/cron.d、authorized_keys）。
		{"/tmp/..", "../../etc/passwd"},
		{"/tmp/..", "etc/cron.d/pwn"},
		{"/tmp/../..", "root/.ssh/authorized_keys"},
		{"/var/www/..", "etc/shadow"},
		// 文件名里的 .. 由 Join+Clean 之后的前缀校验挡住
		{"/tmp", "sub/../../etc/x"},
		{"/tmp", "a/../../../etc/passwd"},
	}
	for _, c := range bad {
		if got, err := safeRemoteJoin(c.dir, c.name); err == nil {
			t.Errorf("safeRemoteJoin(%q,%q) 应被拒绝，得到 %q", c.dir, c.name, got)
		}
	}
}

// decodeLimit 的两条边界：截断的 JSON 要如实报语法错（别说成体积超限）、
// JSON 后面的多余字节要拒掉（原来会被放行）。
func TestDecodeLimitErrorKinds(t *testing.T) {
	var v struct {
		Content string `json:"content"`
	}
	// 限内的截断 JSON：应该是语法错，不是"超过上限"
	err := decodeLimit(httptest.NewRequest(http.MethodPost, "/x",
		strings.NewReader(`{"content":"abc`)), &v, 1<<20)
	if err == nil {
		t.Error("截断的 JSON 应报错")
	} else if strings.Contains(err.Error(), "超过") {
		t.Errorf("限内的语法错不该说成体积超限: %v", err)
	}
	// JSON 后面拖着垃圾
	err = decodeLimit(httptest.NewRequest(http.MethodPost, "/x",
		strings.NewReader(`{"content":"a"}trailing`)), &v, 1<<20)
	if err == nil {
		t.Error("JSON 后面的多余内容应被拒")
	}
}

// 不带令牌访问 /api/ 一律 403（含只读接口）。
func TestControlPlaneAlwaysRequiresToken(t *testing.T) {
	h := newTestServer("secret").Handler()
	paths := []string{
		"/api/health",
		"/api/targets",
		"/api/history",
		"/api/recent",
		"/api/settings",
		"/api/monitor?target_id=x",
		"/api/hostkeys?target_id=x",
		"/api/files/list?target_id=x",
		"/api/logs/files?target_id=x",
		"/api/logs/scan?target_id=x",
		"/api/compliance/history",
		"/api/compliance/checks",
		"/api/threat/stats",
		"/api/db/conns",
		"/api/db/databases?conn_id=x",
	}
	for _, p := range paths {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			req := httptest.NewRequest(m, p, strings.NewReader("{}"))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s 不带令牌应 403，得到 %d", m, p, w.Code)
			}
		}
	}

	// 令牌不对也一样
	req := httptest.NewRequest(http.MethodGet, "/api/targets", nil)
	req.Header.Set("X-Awd-Token", "wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("错误令牌应 403，得到 %d", w.Code)
	}
}

// 带对令牌的 GET 打写 action，必须 405（不是 403，也不是放行）。
func TestWriteActionsRejectWrongMethods(t *testing.T) {
	h := newTestServer("secret").Handler()
	// 只放"读也用 POST、其它方法一律不受理"的路径。
	// /api/targets 的 GET 是合法读（列表），不能算错误方法；
	// /api/history 的 DELETE 也是合法清空，单独在下面测。
	paths := []string{
		"/api/db/delete",
		"/api/db/test",
		"/api/db/query",
		"/api/db/insert",
		"/api/db/update",
		"/api/db/delete-rows",
		"/api/db/create-table",
		"/api/files/delete?target_id=x",
		"/api/files/write?target_id=x",
		"/api/files/mkdir?target_id=x",
		"/api/files/chmod?target_id=x",
		"/api/files/rename?target_id=x",
		"/api/files/upload?target_id=x",
		"/api/threat/prune",
		"/api/threat/clear",
		"/api/compliance/run",
		"/api/compliance/delete?id=1",
		"/api/compliance/clear",
		"/api/logs/scan?target_id=x",
		"/api/prune",
		// 下载目录相关：都是写操作（往本地磁盘写），只允许 POST
		"/api/system/pick-dir",
		"/api/system/save-file",
		"/api/files/save-to-dir?target_id=x",
	}
	for _, p := range paths {
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			req := httptest.NewRequest(m, p, strings.NewReader("{}"))
			req.Header.Set("X-Awd-Token", "secret")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s 应 405，得到 %d", m, p, w.Code)
			}
		}
	}

	// /api/targets：GET 读、POST 存，PUT 应 405
	req := httptest.NewRequest(http.MethodPut, "/api/targets", strings.NewReader("{}"))
	req.Header.Set("X-Awd-Token", "secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT /api/targets 应 405，得到 %d", w.Code)
	}

	// /api/history：用 query 表达清空的 GET/PUT 都要拒
	//（DELETE 是合法清空方法，缺 target_id 时回 400，由另一个测试覆盖）
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		req := httptest.NewRequest(m, "/api/history?action=clear", strings.NewReader("{}"))
		req.Header.Set("X-Awd-Token", "secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /api/history?action=clear 应 405，得到 %d", m, w.Code)
		}
	}
}

// 只读 action 用写方法打过来也该 405（白名单的语义是"只允许 GET"，
// 不是"不要求 POST"）。
func TestReadOnlyActionsRejectWriteMethods(t *testing.T) {
	h := newTestServer("secret").Handler()
	paths := []string{
		"/api/files/list?target_id=x",
		"/api/files/home?target_id=x",
		"/api/files/startdir?target_id=x",
		"/api/files/cwd?target_id=x",
		"/api/files/read?target_id=x&path=/tmp/a",
		"/api/files/download?target_id=x&path=/tmp/a",
		"/api/db/databases?conn_id=x",
		"/api/db/tables?conn_id=x&db=d",
		"/api/db/columns?conn_id=x&db=d&table=t",
		"/api/db/rows?conn_id=x&db=d&table=t",
		"/api/db/ddl?conn_id=x&db=d&table=t",
		"/api/threat/stats",
		"/api/threat/count",
		// 这三条以前漏在白名单外：带对令牌的 POST/PUT /api/compliance/checks
		// 会 200 进处理器（详见 regression_p3_test.go 的同类测试）
		"/api/compliance/checks",
		"/api/compliance/history",
		"/api/compliance/report?id=1",
		// /api/health 与 /api/recent 原来完全不看方法
		"/api/health",
		"/api/recent",
	}
	for _, p := range paths {
		for _, m := range []string{http.MethodPut, http.MethodDelete} {
			req := httptest.NewRequest(m, p, strings.NewReader("{}"))
			req.Header.Set("X-Awd-Token", "secret")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s 应 405，得到 %d", m, p, w.Code)
			}
		}
	}
}

// 静态资源与令牌注入脚本必须无令牌可访问：
// 页面要先加载它们才能拿到令牌，一并要求就成了死锁（要令牌才能取到令牌）。
//
// 这些路径走的是 Host+Origin 兜底，所以要按本机来源构造请求
// （httptest 默认 Host 是 example.com，会被当成外部来源拒掉）。
func TestStaticAssetsNeedNoToken(t *testing.T) {
	h := newTestServer("secret").Handler()
	for _, p := range []string{"/", "/index.html", "/runtime.js"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Host = "127.0.0.1:39123"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		// /index.html 会 301 跳到 /，所以只要求"不是被拒"
		if w.Code >= 400 {
			t.Errorf("%s 应无令牌可访问，得到 %d", p, w.Code)
		}
	}

	// 反过来：非本机来源即使不带令牌也要拒（这些路径没有令牌保护，靠来源兜底）
	req := httptest.NewRequest(http.MethodGet, "/runtime.js", nil)
	req.Host = "evil.example.com"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("外部 Host 取 /runtime.js 应 403，得到 %d", w.Code)
	}
}

// OPTIONS 预检必须放行且带上自定义头，否则浏览器问不出能不能带令牌。
func TestOptionsPreflightAllowed(t *testing.T) {
	h := newTestServer("secret").Handler()
	req := httptest.NewRequest(http.MethodOptions, "/api/targets", nil)
	req.Header.Set("Origin", "http://wails.localhost")
	req.Header.Set("Access-Control-Request-Headers", "x-awd-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("预检应 204，得到 %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Access-Control-Allow-Headers"), "X-Awd-Token") {
		t.Errorf("预检响应应允许 X-Awd-Token，得到 %q", w.Header().Get("Access-Control-Allow-Headers"))
	}
}

// 清空类接口漏传目标时必须 400，不能把"没给参数"解释成"清空整张表"。
func TestClearWithoutTargetIsRejected(t *testing.T) {
	h := newTestServer("secret").Handler()
	cases := []struct {
		path string
		body string
	}{
		{"/api/compliance/clear", "{}"},
		{"/api/history", "{}"},
		{"/api/compliance/clear", ""}, // 空 body
		{"/api/history", "{\"all\":false}"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(c.body))
		req.Header.Set("X-Awd-Token", "secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST %s body=%q 应 400（缺 target_id 且没有显式 all），得到 %d",
				c.path, c.body, w.Code)
		}
	}
}

// 「清空」不能靠查询参数表达：GET 带 query 表达写语义一律拒。
func TestClearViaQueryOnGetIsRejected(t *testing.T) {
	h := newTestServer("secret").Handler()
	for _, p := range []string{
		"/api/history?action=clear",
		"/api/history?action=clear&target_id=x",
		"/api/history?action=anything",
	} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("X-Awd-Token", "secret")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s 应 405，得到 %d", p, w.Code)
		}
	}
}

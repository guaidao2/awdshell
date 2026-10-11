package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/guaidao2/awdshell/internal/infra/logscan"
	"github.com/guaidao2/awdshell/internal/service"
)

// 本文件钉的是第二轮全代码审计里 httpapi 侧剩下的那几条：
//
//	P2-2 days / lines 用 fmt.Sscanf 不判返回值（`days=abc` 静默用默认值）
//	P2-3 POST /api/db/test 试连失败也回 200（前端当成功，失败原因看不到）
//	P2-5 FileServer 对目录与 /index.html 回 301（存在性 oracle）
//	P2-6 Sessions 为 nil 时 /ws/term/* 等路径 nil 解引用 → 500
//	P2-7 /api/compliance/run 把解码错误一律换成"请求体解析失败"
//
// 每条都写成"改回错误版本会红"的形式。这些 service 大多是 nil：
// 判据发生在调用 service 之前，走到 service 会因为 nil panic 而被
// recover 成 500 —— 那也是"判据失效"的信号。

// P2-2：days / lines 给了但解析不出来时必须 400，不能静默用默认值。
//
// 改回错误版本会红：`fmt.Sscanf(v, "%d", &days)` 不判返回值，
// `days=abc` / `lines=abc` / `days=7abc` / `days=3.5` 都会被当成"没给"，
// 静默落到 7 / 2000，用户以为自己设了别的时间窗、别的行数，界面上没有任何提示。
//
// 越界（低2 补的那批）走同一套判据，见下面的 TestIntParamsOutOfRangeAreRejected。
func TestBadDaysAndLinesAreRejected(t *testing.T) {
	h := newTestServer("secret").Handler()

	bad := []struct {
		name, method, path, wantWord string
	}{
		{"days 不是数字", http.MethodGet, "/api/threat/stats?days=abc", "days"},
		{"days 拖尾巴", http.MethodGet, "/api/threat/stats?days=7abc", "days"},
		{"days 是小数", http.MethodGet, "/api/threat/stats?days=3.5", "days"},
		{"lines 不是数字", http.MethodPost, "/api/logs/scan?target_id=t1&lines=abc", "lines"},
		{"lines 拖尾巴", http.MethodPost, "/api/logs/scan?target_id=t1&lines=2000x", "lines"},
	}
	for _, c := range bad {
		var w = doGet(t, h, c.path, "secret")
		if c.method == http.MethodPost {
			w = doPost(t, h, c.path, "secret", "")
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s：%s %s 应 400，得到 %d（body=%s）",
				c.name, c.method, c.path, w.Code, strings.TrimSpace(w.Body.String()))
			continue
		}
		if msg := jsonErr(t, w); !strings.Contains(msg, c.wantWord) {
			t.Errorf("%s：报错要点名是哪个参数不对，得到 %q", c.name, msg)
		}
	}

	// 反向：参数缺失（或只有空白）才用默认值 —— 这两种情况不能也被 400 挡掉。
	// 这两个接口的 service 是 nil，参数没问题时会一路走到 service 再 panic
	// 成 500；只要不是 400 就说明参数这一关放行了。
	//
	// 注意 `days=-1` 曾经写在这个"不该 400"的列表里 —— 那是**旧行为**
	//（越界静默放行，算出未来的 since、返回一个空窗口），低2 修复之后
	// 它必须 400，所以在下面 TestIntParamsOutOfRangeAreRejected 里。
	for _, p := range []string{
		"/api/threat/stats",
		"/api/threat/stats?days=",
		"/api/threat/stats?days=7",
		"/api/threat/stats?days=1",
		"/api/threat/stats?days=365",
	} {
		if w := doGet(t, h, p, "secret"); w.Code == http.StatusBadRequest {
			t.Errorf("GET %s 不该被参数校验挡成 400，得到 %d：%s", p, w.Code, w.Body.String())
		}
	}
	for _, p := range []string{
		"/api/logs/scan?target_id=t1",
		"/api/logs/scan?target_id=t1&lines=",
		"/api/logs/scan?target_id=t1&lines=2000",
		"/api/logs/scan?target_id=t1&lines=1",
		"/api/logs/scan?target_id=t1&lines=20000",
	} {
		if w := doPost(t, h, p, "secret", ""); w.Code == http.StatusBadRequest {
			t.Errorf("POST %s 不该被参数校验挡成 400，得到 %d：%s", p, w.Code, w.Body.String())
		}
	}
}

// 低2：整数参数只判"解析得出来吗"是不够的，越界必须 400 并说清范围。
//
// 改回错误版本会红（复审实测的旧行为）：
//   - `days=-1` → 200，since 被算成**未来时刻**（1791078910037），态势页
//     画出一个空窗口而且什么都不提示；`days=0` 同样 200；
//   - `lines=0` / `lines=-1` → 200，service 再把它静默换成默认的 2000 行，
//     用户以为"我只扫了 1 行"；
//   - `lines=20001` / `days=366` 这类超上限的也被放行，随后被 service
//     悄悄夹回默认值/上限（界面显示按 30000 行扫过，实际 2000 行）。
func TestIntParamsOutOfRangeAreRejected(t *testing.T) {
	h := newTestServer("secret").Handler()

	bad := []struct {
		name, method, path, wantWord string
	}{
		{"days 为负", http.MethodGet, "/api/threat/stats?days=-1", "days"},
		{"days 为零", http.MethodGet, "/api/threat/stats?days=0", "days"},
		{"days 超上限", http.MethodGet, "/api/threat/stats?days=366", "days"},
		{"lines 为零", http.MethodPost, "/api/logs/scan?target_id=t1&lines=0", "lines"},
		{"lines 为负", http.MethodPost, "/api/logs/scan?target_id=t1&lines=-1", "lines"},
		{"lines 超上限", http.MethodPost, "/api/logs/scan?target_id=t1&lines=20001", "lines"},
	}
	for _, c := range bad {
		var w = doGet(t, h, c.path, "secret")
		if c.method == http.MethodPost {
			w = doPost(t, h, c.path, "secret", "")
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s：%s %s 应 400（越界是无效输入，不是「用默认值」），得到 %d（body=%s）",
				c.name, c.method, c.path, w.Code, strings.TrimSpace(w.Body.String()))
			continue
		}
		msg := jsonErr(t, w)
		if !strings.Contains(msg, c.wantWord) {
			t.Errorf("%s：报错要点名是哪个参数，得到 %q", c.name, msg)
		}
		// 光说"参数不对"没用，用户得知道范围是多少
		if !strings.Contains(msg, "范围") {
			t.Errorf("%s：越界的文案要说清允许范围，得到 %q", c.name, msg)
		}
	}
}

// 低2（口径一致）：两个接口用的是同一个解析函数，报错形状也必须一样，
// 而且**边界值必须双向可查**（下限/上限本身合法，越一格就不合法）。
func TestQueryIntIsSharedByBothEndpoints(t *testing.T) {
	// 缺省值原样返回
	if n, err := queryIntRange(nil, "days", 7, 1, 365); err != nil || n != 7 {
		t.Errorf("参数缺失应回默认值 7，得到 %d / %v", n, err)
	}
	// 空白也算缺失（表单有时会发空值）
	if n, err := queryIntRange(newQuery("days", "   "), "days", 7, 1, 365); err != nil || n != 7 {
		t.Errorf("空白值应回默认值 7，得到 %d / %v", n, err)
	}
	// 正常整数
	if n, err := queryIntRange(newQuery("lines", " 500 "), "lines", 2000, 1, 20000); err != nil || n != 500 {
		t.Errorf("lines=500 应解析成 500，得到 %d / %v", n, err)
	}
	// 边界值：正好在下限/上限上要放行（写错成开区间就会把合法值挡掉）
	if n, err := queryIntRange(newQuery("days", "1"), "days", 7, 1, 365); err != nil || n != 1 {
		t.Errorf("days=1 是合法下限，应放行，得到 %d / %v", n, err)
	}
	if n, err := queryIntRange(newQuery("lines", "20000"), "lines", 2000, 1, 20000); err != nil || n != 20000 {
		t.Errorf("lines=20000 是合法上限，应放行，得到 %d / %v", n, err)
	}
	// 越一格就不合法
	for _, c := range []struct {
		name string
		q    map[string][]string
		lo   int
		hi   int
	}{
		{"lines 0", newQuery("lines", "0"), 1, 20000},
		{"lines -1", newQuery("lines", "-1"), 1, 20000},
		{"lines 20001", newQuery("lines", "20001"), 1, 20000},
		{"days 0", newQuery("days", "0"), 1, 365},
		{"days -7", newQuery("days", "-7"), 1, 365},
		{"days 366", newQuery("days", "366"), 1, 365},
	} {
		var n int
		var err error
		if _, isDays := c.q["days"]; isDays {
			n, err = queryIntRange(c.q, "days", 7, c.lo, c.hi)
		} else {
			n, err = queryIntRange(c.q, "lines", 2000, c.lo, c.hi)
		}
		_ = n
		if err == nil {
			t.Errorf("%s：越界必须报错（不能静默落到默认值/被 service 夹回去）", c.name)
			continue
		}
		if !strings.Contains(err.Error(), "范围") {
			t.Errorf("%s：报错要说清允许范围，得到 %q", c.name, err.Error())
		}
	}
	// 解析不了：错误里必须点名参数
	_, err := queryIntRange(newQuery("lines", "abc"), "lines", 2000, 1, 20000)
	if err == nil {
		t.Fatal("lines=abc 必须报错，不能静默用默认值")
	}
	if !strings.Contains(err.Error(), "lines") {
		t.Errorf("报错要点名是哪个参数，得到 %q", err.Error())
	}
}

func newQuery(k, v string) map[string][]string { return map[string][]string{k: {v}} }

// httptestDelete 发一个带令牌的 DELETE（本机来源，否则会被 Host/Origin 兜底挡掉）。
func httptestDelete(h http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	req.Host = testHost
	req.Header.Set("X-Awd-Token", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// P2-3：试连失败必须回非 2xx，但**失败原因仍要在 body 里**。
//
// 改回错误版本会红：老代码回 200 + {"ok":false,...}，HTTP 层面看不出失败
// （通用包装、访问日志、重试逻辑都会当成功），口径也与 monitor/files 的连接类
// 失败（502）不一致；而"保存前先试连、失败了要看到原因"正是这个接口存在的
// 理由，所以原因必须留在 error 字段里给前端读。
func TestDBTestFailureIsNotSuccess(t *testing.T) {
	// kind 非法时 Test() 在碰任何远端之前就返回错误，所以依赖可以全是 nil
	//（pool/targets/store/vault 都不需要）
	s := New(Deps{
		APIToken: "secret",
		Database: service.NewDatabaseService(nil, nil, nil, nil),
		Assets:   fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}},
	})
	h := s.Handler()

	w := doPost(t, h, "/api/db/test", "secret", `{"target_id":"t1","name":"c","kind":"nope"}`)
	if w.Code == http.StatusOK {
		t.Fatalf("试连失败不能回 200（HTTP 层面看不出失败），body=%s", w.Body.String())
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("试连失败应回 502（与 monitor/files 的连接类失败同一口径），得到 %d", w.Code)
	}
	// 原因必须还在 body 里，前端要展示它
	var out struct {
		OK    *bool  `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("失败响应必须是 JSON（前端从 error 字段取原因），解析失败: %v（body=%s）", err, w.Body.String())
	}
	if out.OK == nil || *out.OK {
		t.Errorf("失败时 ok 字段应显式为 false（前端靠它区分），得到 %s", w.Body.String())
	}
	if !strings.Contains(out.Error, "数据库类型") {
		t.Errorf("失败原因要给到前端，实际 error=%q", out.Error)
	}

	// 坏 JSON 仍是 400（别把参数错说成连接失败）
	if w := doPost(t, h, "/api/db/test", "secret", `{"kind":`); w.Code != http.StatusBadRequest {
		t.Errorf("坏 JSON 应 400，得到 %d", w.Code)
	}
}

// P2-5：静态资源一律不产生 301。
//
// 改回错误版本会红：交给 http.FileServer 时，`/index.html` 会 301 跳到 `./`、
// 存在的目录（`/sub`、`/vendor`）会 301 补斜杠 —— 而 301 / 404 / 200 三者
// 合起来就是"这个路径存不存在"的探针（审计实测）。
func TestStaticHandlerNeverRedirects(t *testing.T) {
	assets := fstest.MapFS{
		"index.html":      &fstest.MapFile{Data: []byte("<html>spa</html>")},
		"app.js":          &fstest.MapFile{Data: []byte("console.log(1)")},
		"sub/index.html":  &fstest.MapFile{Data: []byte("<html>sub</html>")},
		"sub/page.js":     &fstest.MapFile{Data: []byte("console.log(2)")},
		"vendor/xterm.js": &fstest.MapFile{Data: []byte("//x")},
	}
	h := New(Deps{APIToken: "secret", Assets: assets}).Handler()

	// 一条都不许是重定向
	for _, p := range []string{
		"/", "/index.html", "/app.js", "/sub", "/sub/", "/sub/index.html",
		"/sub/page.js", "/vendor", "/vendor/", "/vendor/xterm.js",
		"/nope", "/missing.js", "/foo.js/",
	} {
		w := doGet(t, h, p, "")
		if w.Code >= 300 && w.Code < 400 {
			t.Errorf("GET %s 不该回重定向（存在性 oracle），得到 %d → %q",
				p, w.Code, w.Header().Get("Location"))
		}
	}

	// 具体行为：SPA 入口照常打开（-web 模式首页不能坏）
	for _, p := range []string{"/", "/index.html", "/nope"} {
		w := doGet(t, h, p, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "spa") {
			t.Errorf("GET %s 应 200 + index.html，得到 %d：%q", p, w.Code, w.Body.String())
		}
	}
	// 目录里有 index.html 就发它（以前这里同样是 301）
	for _, p := range []string{"/sub", "/sub/", "/sub/index.html"} {
		w := doGet(t, h, p, "")
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "sub") {
			t.Errorf("GET %s 应 200 + sub/index.html，得到 %d：%q", p, w.Code, w.Body.String())
		}
	}
	// 真实存在的资源照常给
	if w := doGet(t, h, "/app.js", ""); w.Code != http.StatusOK {
		t.Errorf("GET /app.js 应 200，得到 %d", w.Code)
	}
	// 缺失的静态资源仍是 404（SPA 回退不能把它回成 200 + HTML）
	for _, p := range []string{"/missing.js", "/foo.js/", "/vendor/none.css"} {
		if w := doGet(t, h, p, ""); w.Code != http.StatusNotFound {
			t.Errorf("GET %s 应 404，得到 %d", p, w.Code)
		}
	}
}

// P2-6：Sessions 为 nil 时不能 nil 解引用（以前被 recover 兜成 500）。
//
// 改回错误版本会红：这些路径会 panic → withCORS 的 recover 回
// 500 "internal error"；用户看到"程序坏了"，而真实原因是这个形态没接终端。
func TestNilSessionsReportsServiceUnavailable(t *testing.T) {
	// 完全不注入 Sessions（Deps{} 里留空）
	h := New(Deps{
		APIToken: "secret",
		Assets:   fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}},
	}).Handler()

	gets := []string{"/api/sessions", "/ws/term/abc", "/ws/term/"}
	for _, p := range gets {
		w := doGet(t, h, p, "secret")
		if w.Code == http.StatusInternalServerError {
			t.Errorf("GET %s 不能是 500（那是 nil 解引用被 recover 兜住了）：%s",
				p, strings.TrimSpace(w.Body.String()))
			continue
		}
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s 应 503（会话服务未启用），得到 %d", p, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), "会话服务未启用") {
			t.Errorf("GET %s 的正文要说清原因，得到 %q", p, w.Body.String())
		}
	}

	posts := []string{"/api/sessions", "/api/sessions/x/attach", "/api/targets/someid"}
	for _, p := range posts {
		w := doPost(t, h, p, "secret", `{"target_id":"t1"}`)
		if w.Code == http.StatusInternalServerError {
			t.Errorf("POST %s 不能是 500（nil 解引用）：%s", p, strings.TrimSpace(w.Body.String()))
			continue
		}
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("POST %s 应 503，得到 %d", p, w.Code)
		}
	}

	w := httptestDelete(h, "/api/sessions/x", "secret")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("DELETE /api/sessions/x 应 503，得到 %d", w.Code)
	}

	// 反向：注入了会话服务时这条判据不能把请求一起挡掉
	// （空会话表 → 保持原来的 403，不区分会话是否存在）
	withSessions := New(Deps{
		APIToken: "secret",
		Sessions: service.NewSessionService(nil, nil, nil),
		Assets:   fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<html></html>")}},
	}).Handler()
	if w := doGet(t, withSessions, "/ws/term/does-not-exist", "secret"); w.Code != http.StatusForbidden {
		t.Errorf("会话服务已注入时仍应是 403（不区分会话存在与否），得到 %d", w.Code)
	}
}

// P2-7：请求体解析失败要说清是"超过上限"还是"JSON 格式不对"。
//
// 改回错误版本会红：老代码一律回 errText("请求体解析失败")，
// 9MB 的 body 与一个坏 JSON 拿到同一句话，用户不知道该改大小还是改格式。
func TestComplianceRunReportsDecodeReason(t *testing.T) {
	h := newTestServer("secret").Handler()

	// 1) JSON 格式错：要点名格式
	w := doPost(t, h, "/api/compliance/run", "secret", `{"target_id":`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("坏 JSON 应 400，得到 %d", w.Code)
	} else if msg := jsonErr(t, w); !strings.Contains(msg, "JSON") {
		t.Errorf("坏 JSON 的文案要说明是格式问题，得到 %q", msg)
	}

	// 2) 体积超限：要说明是超过上限（不是格式、也不是缺字段）
	huge := `{"target_id":"` + strings.Repeat("a", 9<<20) + `"}`
	w = doPost(t, h, "/api/compliance/run", "secret", huge)
	if w.Code != http.StatusBadRequest {
		t.Errorf("9MB body 应 400，得到 %d", w.Code)
	} else if msg := jsonErr(t, w); !strings.Contains(msg, "超过") {
		t.Errorf("超限的文案要说明是体积问题，得到 %q", msg)
	}

	// 3) 空 body：说清是空的/缺 target_id，不能把 io.EOF 原文给用户
	w = doPost(t, h, "/api/compliance/run", "secret", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("空 body 应 400，得到 %d", w.Code)
	} else {
		msg := jsonErr(t, w)
		if strings.Contains(msg, "EOF") {
			t.Errorf("空 body 不该把 io.EOF 原文回给用户，得到 %q", msg)
		}
		if !strings.Contains(msg, "target_id") {
			t.Errorf("空 body 的文案要说清缺什么，得到 %q", msg)
		}
	}
}

// P2-1（契约）：截断字段的 JSON 名必须与前端读的一致。
//
// service.ScanLog 返回的就是 logscan.Result，handler 直接 writeJSON 出去，
// 所以这四个字段的 tag 一变，前端的"结果不完整"提示就静默失效
// （frontend/dist/logscan.js 读的是 truncated / truncated_reason /
// stopped_at_line / dropped_hits）。这条把名字钉住。
func TestScanResultTruncationFieldNames(t *testing.T) {
	raw, err := json.Marshal(logscan.Result{
		Path:            "/var/log/nginx/access.log",
		Truncated:       true,
		TruncatedReason: "扫描时间预算耗尽",
		StoppedAtLine:   1234,
		DroppedHits:     7,
	})
	if err != nil {
		t.Fatalf("序列化扫描结果失败: %v", err)
	}
	got := string(raw)
	for _, key := range []string{"truncated", "truncated_reason", "stopped_at_line", "dropped_hits"} {
		if !strings.Contains(got, `"`+key+`"`) {
			t.Errorf("扫描结果的 JSON 里缺少 %q（前端要读它来提示结果不完整）：%s", key, got)
		}
	}
}

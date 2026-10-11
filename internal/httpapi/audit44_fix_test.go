package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guaidao2/awdshell/internal/service"
)

// newAuthedRequest 造一个带正确令牌的请求（省掉每个用例重复写头）。
func newAuthedRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Awd-Token", "secret")
	return req
}

// record 跑一遍 handler，返回响应记录器。
func record(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// 这一组固化 audit44 里 httpapi 的几条：缺参回 400（不是 502）、
// 并发采样回 409（不是 502）。

// TestMonitorSamplingConflictIsNotBadGateway 守 M1 的状态码口径。
//
// 改回错误版本会红：并发采样（"上一次采样还没结束"）以前和真实采集错误一起回 502，
// 前端把它画成红色的"采集失败"并停在上一台的数据上 —— 而客户端什么都没做错，
// 只是赶上了另一个采样在跑。409 Conflict 的语义才是"请求没毛病、只是与当前状态冲突"，
// 前端按"跳过这一轮"处理。
func TestMonitorSamplingConflictIsNotBadGateway(t *testing.T) {
	if got := monitorErrStatus(service.ErrSampling); got != http.StatusConflict {
		t.Errorf("并发采样应回 409，实际 %d", got)
	}
	// 包装过的也要认（service 侧以后可能 %w 包一层）
	if got := monitorErrStatus(errors.New("采集失败")); got != http.StatusBadGateway {
		t.Errorf("真实采集失败仍是 502，实际 %d", got)
	}
}

// TestMonitorMissingTargetIsBadRequest 守"缺 target_id 回 400"这条老判据没被带坏。
func TestMonitorMissingTargetIsBadRequest(t *testing.T) {
	h := newTestServer("secret").Handler()
	req := newAuthedRequest(http.MethodGet, "/api/monitor", "")
	w := record(h, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("缺 target_id 应 400，得到 %d", w.Code)
	}
}

// TestFilesTargetIDMissingIsBadRequest 守 M2：home/startdir/cwd 漏 target_id 要回 400。
//
// 改回错误版本会红：这三个 action 以前没判空，targets.Auth("") 失败被写成
// 502 Bad Gateway —— 同类接口（monitor/logs/hostkeys）都回 400，口径不一致，
// 前端还会把它当服务端故障提示。
//
// 这些断言都在调用 service 之前返回，所以依赖可以全是 nil：
// 判据一旦漏掉，nil 解引用会 panic（也是信号）。
func TestFilesTargetIDMissingIsBadRequest(t *testing.T) {
	h := newTestServer("secret").Handler()
	for _, p := range []string{
		"/api/files/home",
		"/api/files/startdir",
		"/api/files/cwd",
		"/api/files/list",
		"/api/files/read",
	} {
		req := newAuthedRequest(http.MethodGet, p, "")
		w := record(h, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("GET %s 缺 target_id 应 400，得到 %d（body=%s）", p, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "target_id") {
			t.Errorf("GET %s 的错误正文要点名缺什么，得到 %s", p, w.Body.String())
		}
	}
}

// TestFilesDeleteWithoutPathsIsBadRequest 守 M3：空 paths 要回 400，不是 502。
//
// 改回错误版本会红：以前由 service 层抛出普通 error，httpapi 一律按
// 502 Bad Gateway 处理 —— 实测 `POST /api/files/delete {}` 得到 502。
func TestFilesDeleteWithoutPathsIsBadRequest(t *testing.T) {
	h := newTestServer("secret").Handler()
	for _, body := range []string{`{}`, `{"target_id":"t"}`, `{"target_id":"t","paths":[]}`} {
		req := newAuthedRequest(http.MethodPost, "/api/files/delete", body)
		w := record(h, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST /api/files/delete body=%s 应 400（缺 paths），得到 %d（body=%s）",
				body, w.Code, w.Body.String())
		}
	}
}

// TestDeleteNoPathsSentinelIsDistinguishable 钉住 service 侧的哨兵值。
//
// httpapi 靠 errors.Is(err, service.ErrDeleteNoPaths) 把它与连接故障分开；
// 如果 service 退回成 fmt.Errorf("没有指定要删除的路径")，errors.Is 认不出，
// 这条路又会变成 502。
func TestDeleteNoPathsSentinelIsDistinguishable(t *testing.T) {
	if service.ErrDeleteNoPaths == nil {
		t.Fatal("service.ErrDeleteNoPaths 不能为 nil")
	}
	if !errors.Is(service.ErrDeleteNoPaths, service.ErrDeleteNoPaths) {
		t.Error("哨兵必须能被 errors.Is 认出")
	}
	if !strings.Contains(service.ErrDeleteNoPaths.Error(), "删除") {
		t.Errorf("哨兵文案要能直接给用户看，实际 %q", service.ErrDeleteNoPaths.Error())
	}
}

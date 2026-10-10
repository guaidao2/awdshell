package httpapi

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// maxHistoryLimit 是核查历史一次最多返回的条数（与 handleHistory 的 200
// 同一类保护：报告里带完整 JSON，一次读太多会把内存顶起来）。
const maxHistoryLimit = 500

// handleCompliance 处理 /api/compliance/*：
//
//	GET  /api/compliance/checks  列出检查项
//	POST /api/compliance/run     在目标机上执行核查
func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/compliance/")

	// 只读 action 明确只允许 GET（与 files/database/threat 同一口径）。
	// 以前这三条没有方法校验：带对令牌的 POST/PUT /api/compliance/checks 能进处理器，
	// 于是"新增只读 action 忘了归类"这件事再也不会在测试里冒出来（白名单没暴露缺口）。
	switch action {
	case "checks", "history", "report":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}

	switch action {
	case "checks":
		checks, problems, err := s.Compliance.Checks()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"checks": checks, "problems": problems})

	case "run":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			TargetID string   `json:"target_id"`
			Only     []string `json:"only"`
		}
		// 走带体积上限的解析：裸 Decode 会把这个 body 整个吃进内存（实测 9MB）
		if err := decode(r, &body); err != nil {
			writeErr(w, http.StatusBadRequest, errText("请求体解析失败"))
			return
		}
		if strings.TrimSpace(body.TargetID) == "" {
			writeErr(w, http.StatusBadRequest, errText("缺少 target_id"))
			return
		}
		// 带上请求的 context：一轮 60+ 项可能跑几分钟，用户关页面/切走时
		// 服务端应当提前收手，而不是白跑完再把结果丢掉。
		report, err := s.Compliance.RunContext(r.Context(), body.TargetID, body.Only)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, report)

	case "history":
		// limit 以前硬编码 30，前端传多少都被丢掉；现在按请求取，上限 500。
		// 注释一直写着"上限 500"，但代码里没有夹取 —— 传 limit=100000 会让
		// store 一次把全部报告读出来（每份带完整 JSON），把内存顶起来。
		// 这里补上真实的上限。
		limit := 30
		if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
			limit = n
		}
		if limit > maxHistoryLimit {
			limit = maxHistoryLimit
		}
		list, err := s.Compliance.History(r.URL.Query().Get("target_id"), limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"reports": list})

	// 删一条 / 清空：保留期清理是后台定时的事，用户还得能自己删。
	//
	// 这两个都是毁伤性动作，**必须限 POST**：控制面令牌是按"非 GET"强制加的，
	// 如果它们能被 GET 触发，就等于绕过令牌（GET 只走 Host+Origin 兜底，
	// 而本机来源是被放行的，一个裸 GET 就能把数据全清掉）。
	case "delete":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// id 既允许 query 也允许 body，前端用 query
		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			var in struct {
				ID int64 `json:"id"`
			}
			// 允许空 body（前端用 query 传 id）；但**格式错的 JSON 要如实报**，
			// 否则用户发了个坏请求，收到的是"缺少 id"而不是"JSON 格式错误"。
			// 走 decodeLimit 而不是裸 Decode：这里以前没有体积上限。
			if err := decodeLimit(r, &in, maxBodyBytes); err != nil && !errors.Is(err, io.EOF) {
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			if in.ID > 0 {
				idStr = strconv.FormatInt(in.ID, 10)
			}
		}
		id, err := strconv.ParseInt(strings.TrimSpace(idStr), 10, 64)
		if err != nil || id <= 0 {
			writeErr(w, http.StatusBadRequest, errText("缺少 id"))
			return
		}
		n, err := s.Compliance.DeleteReport(id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if n == 0 {
			// 删一个不存在的 id 不该回 ok，否则界面会 toast「已删掉那条记录」
			writeErr(w, http.StatusNotFound, errText("这条记录不存在（可能已被删除）"))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": n})

	case "clear":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var in struct {
			TargetID string `json:"target_id"`
			All      bool   `json:"all"`
		}
		// 允许空 body：那时按 body 里的 target_id 处理。
		// 不从 query 取 target_id —— query 表达写语义本身就该避免
		// （handleHistory 专门为"GET 带 action"加了 405，方向要一致）。
		// 格式错的 JSON 要如实报，不能静默当"没给参数"。
		// 走 decodeLimit 而不是裸 Decode：这里以前没有体积上限。
		if err := decodeLimit(r, &in, maxBodyBytes); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		target := in.TargetID
		// 只有显式 all:true 才走"全清"。漏传参数的默认方向必须是安全的，
		// 不能是"没给目标 = 清空整张表"。
		if target == "" && !in.All {
			writeErr(w, http.StatusBadRequest, errText("缺少 target_id（要清空全部请显式传 all=true）"))
			return
		}
		if in.All {
			target = ""
		}
		n, err := s.Compliance.ClearReports(target)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": n})

	case "report":
		id, perr := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
		if perr != nil || id <= 0 {
			writeErr(w, http.StatusBadRequest, errText("缺少 id"))
			return
		}
		rep, err := s.Compliance.ReportByID(id)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		if rep == nil {
			writeErr(w, http.StatusNotFound, errText("找不到这份报告"))
			return
		}
		writeJSON(w, http.StatusOK, rep)

	default:
		http.NotFound(w, r)
	}
}

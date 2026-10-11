package httpapi

import (
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/guaidao2/awdshell/internal/infra/dbx"
	"github.com/guaidao2/awdshell/internal/service"
)

// handleDatabase 处理 /api/db/*：
//
//	GET  /api/db/conns?target_id=     列出连接配置
//	POST /api/db/conns                保存连接配置
//	POST /api/db/delete               删除连接配置
//	POST /api/db/test                 试连（保存前也能验）
//	POST /api/db/query                执行 SQL
//	GET  /api/db/databases?conn_id=   列出库
//	GET  /api/db/tables?conn_id=&db=  列出表
//	GET  /api/db/columns?...          列出字段
func (s *Server) handleDatabase(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/db/")
	q := r.URL.Query()

	// 只读 action 明确只允许 GET，写 action 明确只允许 POST。
	// 用显式声明而不是"默认分支兜底"：只读的白名单若只是"不要求 POST"，
	// PUT/DELETE 打过来照样会被受理；而且以后新增 action 忘了归类时，
	// 宁可立刻报 405 让人发现，也别悄悄放行一个方法。
	switch action {
	case "databases", "tables", "columns", "rows", "ddl":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	case "conns":
		// 列表 GET、保存 POST，下面各自判断
	default:
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}

	switch action {
	case "conns":
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			// 以前只判了 GET，PUT/DELETE 会掉进"保存配置"分支
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodGet {
			list, err := s.Database.Conns(q.Get("target_id"))
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"conns": list})
			return
		}
		var in service.DBConnInput
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		saved, err := s.Database.SaveConn(in)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)

	case "delete":
		var in struct {
			ID string `json:"id"`
		}
		if err := decode(r, &in); err != nil || in.ID == "" {
			writeErr(w, http.StatusBadRequest, errText("缺少 id"))
			return
		}
		if err := s.Database.DeleteConn(in.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case "test":
		var in service.DBConnInput
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		msg, err := s.Database.Test(in)
		if err != nil {
			// 试连失败必须回非 2xx：以前回 200 + {"ok":false}，HTTP 层面看不出
			// 失败 —— 通用包装/访问日志/重试逻辑都会把它当成功，口径也与
			// monitor / files 的连接类失败不一致（那边是 502 Bad Gateway）。
			//
			// **原因仍留在 body 的 error 字段里**："保存前先试连、失败了要看到
			// 原因"这个功能不受影响（前端的 req() 在非 2xx 时会读 error 字段
			// 抛错，测试按钮把它显示成"测试失败：<原因>"）。
			log.Printf("数据库试连失败: %v", err)
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})

	case "query":
		var in struct {
			ConnID  string `json:"conn_id"`
			SQL     string `json:"sql"`
			MaxRows int    `json:"max_rows"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if strings.TrimSpace(in.ConnID) == "" {
			writeErr(w, http.StatusBadRequest, errText("请先选择一条连接"))
			return
		}
		// max_rows 先按统一的一套常量夹一次（见 service.MaxQueryRows）：
		// service 层还会按连接的配置上限再夹一次，两层都用同一组常量，
		// 不会出现"某处写 5000、某处写 1000"这种对不上的口径。
		in.MaxRows = service.ClampRequestedRows(in.MaxRows)
		res, err := s.Database.Query(in.ConnID, in.SQL, in.MaxRows)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, res)

	case "databases":
		list, err := s.Database.Databases(q.Get("conn_id"))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"databases": list})

	case "tables":
		list, err := s.Database.Tables(q.Get("conn_id"), q.Get("db"))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"tables": list})

	case "columns":
		list, err := s.Database.Columns(q.Get("conn_id"), q.Get("db"), q.Get("schema"), q.Get("table"))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"columns": list})

	// ---------- 图形化操作 ----------

	case "rows":
		// 一页的行数：默认值与上限都引用 service 里那套常量（不再写 100 这个字面量）。
		// 越界就落回默认值 —— 与 dbx 里那条夹取（size<=0 或 >1000 → 100）同一口径，
		// 所以这里夹一次不改变原来的实际行为。
		size := atoiDefault(q.Get("size"), service.DefaultPageRows)
		if size <= 0 || size > service.MaxPageRows {
			size = service.DefaultPageRows
		}
		page, err := s.Database.Rows(q.Get("conn_id"), tableRef(q), dbx.RowQuery{
			Page:    atoiDefault(q.Get("page"), 1),
			Size:    size,
			OrderBy: q.Get("order"),
			Desc:    q.Get("dir") == "desc",
			Filter:  q.Get("filter"),
		})
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, page)

	case "insert":
		var in struct {
			ConnID string         `json:"conn_id"`
			Ref    dbx.TableRef   `json:"ref"`
			Values map[string]any `json:"values"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		n, err := s.Database.InsertRow(in.ConnID, in.Ref, in.Values)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "affected": n})

	case "update":
		var in struct {
			ConnID string         `json:"conn_id"`
			Ref    dbx.TableRef   `json:"ref"`
			Key    map[string]any `json:"key"`
			Values map[string]any `json:"values"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		n, err := s.Database.UpdateRow(in.ConnID, in.Ref, in.Key, in.Values)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "affected": n})

	case "delete-rows":
		var in struct {
			ConnID string           `json:"conn_id"`
			Ref    dbx.TableRef     `json:"ref"`
			Keys   []map[string]any `json:"keys"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		n, err := s.Database.DeleteRows(in.ConnID, in.Ref, in.Keys)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "affected": n})

	case "ddl":
		out, err := s.Database.ShowCreate(q.Get("conn_id"), tableRef(q))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ddl": out})

	case "create-table":
		var in struct {
			ConnID string        `json:"conn_id"`
			Spec   dbx.TableSpec `json:"spec"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Database.CreateTable(in.ConnID, in.Spec); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	default:
		http.NotFound(w, r)
	}
}

// tableRef 从查询参数里取表定位信息。
func tableRef(q url.Values) dbx.TableRef {
	return dbx.TableRef{Database: q.Get("db"), Schema: q.Get("schema"), Table: q.Get("table")}
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

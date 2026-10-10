package httpapi

import (
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
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
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
		page, err := s.Database.Rows(q.Get("conn_id"), tableRef(q), dbx.RowQuery{
			Page:    atoiDefault(q.Get("page"), 1),
			Size:    atoiDefault(q.Get("size"), 100),
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

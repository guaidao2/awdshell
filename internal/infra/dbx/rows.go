package dbx

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ---------- 图形化操作需要的能力 ----------
//
// SQL 编辑器只能满足"会写 SQL 的人"。这里补的是图形化那一半：
// 分页读表数据、按主键增删改、读字段详情、建表。
//
// 安全边界：标识符（库/表/列/类型）一律走引用与白名单，值一律走占位符，
// 只有"筛选条件"是用户自己写的表达式（本来 SQL 编辑器就能写，不算新增面）。

// TableRef 定位一张表。
type TableRef struct {
	Database string `json:"database"` // MySQL 用
	Schema   string `json:"schema"`   // PostgreSQL 用
	Table    string `json:"table"`
}

// ColumnInfo 是字段的完整信息。
type ColumnInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Nullable   bool   `json:"nullable"`
	PrimaryKey bool   `json:"primary_key"`
	AutoInc    bool   `json:"auto_increment"`
	Default    string `json:"default"`
	Comment    string `json:"comment"`
}

// RowPage 是一页表数据。
type RowPage struct {
	Columns    []ColumnInfo `json:"columns"`
	Rows       [][]string   `json:"rows"`
	Total      int64        `json:"total"`
	Page       int          `json:"page"`
	Size       int          `json:"size"`
	PrimaryKey []string     `json:"primary_key"`
	// Editable 为假时界面要禁掉编辑：没有主键就没法安全定位一行
	Editable bool   `json:"editable"`
	Note     string `json:"note"`
}

// RowQuery 是读表数据的条件。
type RowQuery struct {
	Page    int
	Size    int
	OrderBy string
	Desc    bool
	Filter  string // WHERE 片段，空表示全部
}

// quote 给标识符加引用，按方言选引号，并把引号字符翻倍转义。
func (c *Conn) quote(name string) string {
	q := `"`
	if c.kind == KindMySQL {
		q = "`"
	}
	return q + strings.ReplaceAll(name, q, q+q) + q
}

// qualified 返回 "库.表" 或 "schema.表"。
func (c *Conn) qualified(ref TableRef) string {
	if c.kind == KindMySQL {
		if ref.Database != "" {
			return c.quote(ref.Database) + "." + c.quote(ref.Table)
		}
		return c.quote(ref.Table)
	}
	s := ref.Schema
	if s == "" {
		s = "public"
	}
	return c.quote(s) + "." + c.quote(ref.Table)
}

// checkIdent 拒绝把危险字符塞进标识符或类型里。
// 标识符本身走引用，但类型是拼进 DDL 的，必须拦。
func checkIdent(s string) error {
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("名称不能为空")
	}
	if strings.ContainsAny(s, ";'\"`\\ \t\n\r") {
		return fmt.Errorf("名称里不能有空格、引号或分号：%s", s)
	}
	return nil
}

// typeRe 限制建表时用的类型写法。
//
// 之前的白名单允许逗号与空格，于是 "int, evil text" 能塞进额外列定义
// （虽然起不了新语句 —— 分号挡住了 —— 但它能改写列清单的形状，名实不符）。
var typeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_ ]*(\(\s*\d+(\s*,\s*\d+)?\s*\))?(\[\])?$`)

// escapeString 转义字符串字面量。
//
// MySQL/MariaDB 默认 sql_mode 下反斜杠是字符串里的转义符
// （NO_BACKSLASH_ESCAPES 不在默认值里），只翻倍单引号的话，
// 默认值填 C:\temp\ 这种就把语句拼坏了（字符串未闭合，报 1064）。
// PostgreSQL 的 standard_conforming_strings=on 不受反斜杠影响，一起转义也无害。
func escapeString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "'", "''")
}

// checkType 校验建表时用的类型（它是要拼进 DDL 的）。
func checkType(s string) error {
	t := strings.TrimSpace(s)
	if t == "" {
		return fmt.Errorf("字段类型不能为空")
	}
	if !typeRe.MatchString(t) {
		return fmt.Errorf("这个字段类型写法不支持：%s（示例：varchar(64)、int、numeric(10,2)、timestamp、text）", t)
	}
	return nil
}

// ColumnsInfo 读字段详情（含主键与自增标记）。
func (c *Conn) ColumnsInfo(ctx context.Context, ref TableRef) ([]ColumnInfo, error) {
	// 这两个函数自身也导出，调用方不一定先在 SelectRows/InsertRow 里过一遍校验。
	// 库/schema 名同样是拼进 information_schema 查询参数的标识符，入口各校验一次
	// 才算一致；空串合法（MySQL 用连接默认库、PG 回退 public）。
	if err := checkTableRef(ref); err != nil {
		return nil, err
	}
	var q string
	var args []any
	if c.kind == KindMySQL {
		q = `SELECT column_name, column_type, is_nullable, column_key, extra,
		            COALESCE(column_default, ''), COALESCE(column_comment, '')
		      FROM information_schema.columns
		      WHERE table_schema = ` + c.placeholder(1) + ` AND table_name = ` + c.placeholder(2) + `
		      ORDER BY ordinal_position`
		args = []any{ref.Database, ref.Table}
	} else {
		s := ref.Schema
		if s == "" {
			s = "public"
		}
		q = `SELECT column_name, COALESCE(udt_name, data_type), is_nullable, '', '',
		            COALESCE(column_default, ''), ''
		      FROM information_schema.columns
		      WHERE table_schema = ` + c.placeholder(1) + ` AND table_name = ` + c.placeholder(2) + `
		      ORDER BY ordinal_position`
		args = []any{s, ref.Table}
	}

	rows, err := c.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, tidyErr(err)
	}
	defer rows.Close()

	out := []ColumnInfo{}
	for rows.Next() {
		var ci ColumnInfo
		var nullable, key, extra string
		if err := rows.Scan(&ci.Name, &ci.Type, &nullable, &key, &extra, &ci.Default, &ci.Comment); err != nil {
			return nil, tidyErr(err)
		}
		ci.Nullable = strings.EqualFold(nullable, "YES")
		ci.PrimaryKey = strings.EqualFold(key, "PRI")
		ci.AutoInc = strings.Contains(strings.ToLower(extra), "auto_increment") ||
			strings.Contains(strings.ToLower(ci.Default), "nextval(")
		out = append(out, ci)
	}
	if err := rows.Err(); err != nil {
		return nil, tidyErr(err)
	}

	// PostgreSQL 的 information_schema.columns 不带主键标记，单独查一次
	if c.kind == KindPostgres {
		pk, err := c.PrimaryKeys(ctx, ref)
		if err == nil && len(pk) > 0 {
			set := map[string]bool{}
			for _, n := range pk {
				set[n] = true
			}
			for i := range out {
				if set[out[i].Name] {
					out[i].PrimaryKey = true
				}
			}
		}
	}
	return out, nil
}

// PrimaryKeys 返回主键列（按定义顺序）；没有主键时返回空切片。
func (c *Conn) PrimaryKeys(ctx context.Context, ref TableRef) ([]string, error) {
	// 与 ColumnsInfo 同理：自身导出，不能指望调用方先校验。
	if err := checkTableRef(ref); err != nil {
		return nil, err
	}
	var q string
	var args []any
	if c.kind == KindMySQL {
		q = `SELECT column_name FROM information_schema.key_column_usage
		      WHERE table_schema = ` + c.placeholder(1) + ` AND table_name = ` + c.placeholder(2) + `
		        AND constraint_name = 'PRIMARY'
		      ORDER BY ordinal_position`
		args = []any{ref.Database, ref.Table}
	} else {
		s := ref.Schema
		if s == "" {
			s = "public"
		}
		q = `SELECT kcu.column_name
		      FROM information_schema.table_constraints tc
		      JOIN information_schema.key_column_usage kcu
		        ON kcu.constraint_name = tc.constraint_name
		       AND kcu.table_schema = tc.table_schema
		      WHERE tc.constraint_type = 'PRIMARY KEY'
		        AND tc.table_schema = ` + c.placeholder(1) + ` AND tc.table_name = ` + c.placeholder(2) + `
		      ORDER BY kcu.ordinal_position`
		args = []any{s, ref.Table}
	}
	rows, err := c.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, tidyErr(err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, tidyErr(err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// checkTableRef 校验引用的库/schema 名。
//
// 它们和表名一样会被 quote() 包进标识符（`db`.`t`、`"s"."t"`），但以前只有表名
// 过 checkIdent。空串是合法的（MySQL 用连接默认库、PG 回退 public），非空才校验。
func checkTableRef(ref TableRef) error {
	for _, s := range []string{ref.Database, ref.Schema} {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if err := checkIdent(s); err != nil {
			return err
		}
	}
	return nil
}

// maxRowPage 是分页页码的上限。
//
// 存在的理由只有一个：offset = (page-1)*size 会**整数溢出**。
// page = 2^62、size = 100 时乘积回绕成负数，拼出来的是 `OFFSET -1000` ——
// MySQL 直接报语法错（PG 报 OFFSET must not be negative），
// 而不是把错误挡在本地。前端传个 page=99999999999999999999 就能触发。
// 1e6 页 × 100 行 = 1 亿行，远超"页面点得出来的"范围，正常使用碰不到。
const maxRowPage = 1_000_000

// whereClause 把用户输入的筛选片段整理成 WHERE 子句。
//
// 只是防手滑，不是安全边界：SQL 编辑器本来就能写任意语句。但筛选片段是拼进
// `SELECT ... WHERE <片段> ORDER BY ... LIMIT ...` 中间的，所以要保证它不能
// 把后面的 ORDER BY / LIMIT 吃掉、也不能借机落文件。
//
// 判据分两层：
//   - 注释标记（`--` / `#` / `/*`）与分号查**原文**：flattenSQL 会把整段注释
//     连标记一起丢掉（`1=1 #` 压平后就是 `1=1`），查压平结果会漏掉 `1=1 #`
//     这种"把 ORDER BY / LIMIT 一起注释掉、一次把全表拉回来"的写法。
//     注释与分号一拦，`INTO--\nOUTFILE` 这类靠符号切分的变体其实已经进不来。
//   - INTO 形态查**压平后的词序列**：`INTO  OUTFILE`（双空格）、
//     `INTO/**/OUTFILE` 这类纯粹靠分隔符变化的写法，字面量子串匹配认不出，
//     压平成词序列之后才拦得住（与 IsReadOnlySQL 同一套语义）。
func whereClause(filter string) (string, error) {
	s := strings.TrimSpace(filter)
	if s == "" {
		return "", nil
	}
	// 只做**否定判断**：这里不能用 flattenSQL 的输出拼语句 —— 它会把字符串
	// 字面量外的空白压成一个空格，虽然不影响语义，但没有必要改用户写的东西。
	// 注释标记查**原文**（理由见函数注释），分号与 INTO 形态查压平结果。
	for _, bad := range []string{";", "--", "#", "/*", "*/"} {
		if strings.Contains(s, bad) {
			return "", fmt.Errorf("筛选条件里不能出现 %s（多语句请用上面的 SQL 编辑器）", bad)
		}
	}
	flat := flattenSQL(strings.ToLower(s))
	if strings.Contains(flat, ";") {
		return "", fmt.Errorf("筛选条件里不能出现 %s（多语句请用上面的 SQL 编辑器）", ";")
	}
	words := wordsOnly(flat)
	if containsWordPair(words, "into", "outfile") || containsWordPair(words, "into", "dumpfile") {
		return "", fmt.Errorf("筛选条件里不能出现 INTO OUTFILE / INTO DUMPFILE（会在目标机落文件）")
	}
	// `INTO <标识符>`：PG 会建表、MySQL 会给变量赋值。outfile/dumpfile 上面已单独判过。
	if selectIntoTable(words) {
		return "", fmt.Errorf("筛选条件里不能出现 INTO（PG 会建表、MySQL 会赋值变量，请用上面的 SQL 编辑器）")
	}
	return " WHERE " + s, nil
}

// SelectRows 分页读一张表的数据。
func (c *Conn) SelectRows(ctx context.Context, ref TableRef, rq RowQuery) (*RowPage, error) {
	if err := checkTableRef(ref); err != nil {
		return nil, err
	}
	if err := checkIdent(ref.Table); err != nil {
		return nil, err
	}
	if rq.Size <= 0 || rq.Size > 1000 {
		rq.Size = 100
	}
	if rq.Page <= 0 {
		rq.Page = 1
	}
	// 页码上限：没有它的话 (page-1)*size 会整数溢出，拼出负的 OFFSET（见 maxRowPage）
	if rq.Page > maxRowPage {
		return nil, fmt.Errorf("页码太大（上限 %d）", maxRowPage)
	}

	cols, err := c.ColumnsInfo(ctx, ref)
	if err != nil {
		return nil, err
	}
	pk, _ := c.PrimaryKeys(ctx, ref)

	where, err := whereClause(rq.Filter)
	if err != nil {
		return nil, err
	}

	// 排序字段必须真实存在，避免把任意文本拼进 ORDER BY
	var order string
	if rq.OrderBy != "" {
		for _, col := range cols {
			if col.Name == rq.OrderBy {
				dir := " ASC"
				if rq.Desc {
					dir = " DESC"
				}
				order = " ORDER BY " + c.quote(col.Name) + dir
				break
			}
		}
	}

	page := &RowPage{
		Columns:    cols,
		Rows:       [][]string{},
		Page:       rq.Page,
		Size:       rq.Size,
		PrimaryKey: pk,
		Editable:   len(pk) > 0,
	}
	if !page.Editable {
		page.Note = "这张表没有主键，无法安全定位单行，所以只读；要改数据请用 SQL 编辑器"
	}

	qual := c.qualified(ref)
	if err := c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+qual+where).Scan(&page.Total); err != nil {
		return nil, tidyErr(err)
	}

	offset := (rq.Page - 1) * rq.Size
	q := "SELECT * FROM " + qual + where + order +
		" LIMIT " + strconv.Itoa(rq.Size) + " OFFSET " + strconv.Itoa(offset)

	rows, err := c.db.QueryContext(ctx, q)
	if err != nil {
		return nil, tidyErr(err)
	}
	defer rows.Close()

	names, err := rows.Columns()
	if err != nil {
		return nil, tidyErr(err)
	}
	vals := make([]any, len(names))
	ptrs := make([]any, len(names))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return nil, tidyErr(err)
		}
		row := make([]string, len(names))
		for i, v := range vals {
			row[i] = formatValue(v)
		}
		page.Rows = append(page.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, tidyErr(err)
	}
	return page, nil
}

// pickValues 按列名过滤入参，只保留表里真实存在的列，值走占位符。
func (c *Conn) pickValues(cols []ColumnInfo, values map[string]any) (names []string, holders []string, args []any) {
	i := 1
	for _, col := range cols {
		v, ok := values[col.Name]
		if !ok {
			continue
		}
		names = append(names, c.quote(col.Name))
		holders = append(holders, c.placeholder(i))
		args = append(args, v)
		i++
	}
	return
}

// InsertRow 插入一行。
func (c *Conn) InsertRow(ctx context.Context, ref TableRef, values map[string]any) (int64, error) {
	if err := checkTableRef(ref); err != nil {
		return 0, err
	}
	if err := checkIdent(ref.Table); err != nil {
		return 0, err
	}
	cols, err := c.ColumnsInfo(ctx, ref)
	if err != nil {
		return 0, err
	}
	names, holders, args := c.pickValues(cols, values)
	if len(names) == 0 {
		return 0, fmt.Errorf("没有要写入的字段")
	}
	q := "INSERT INTO " + c.qualified(ref) +
		" (" + strings.Join(names, ", ") + ") VALUES (" + strings.Join(holders, ", ") + ")"
	r, err := c.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, tidyErr(err)
	}
	n, _ := r.RowsAffected()
	return n, nil
}

// UpdateRow 按主键更新一行。
func (c *Conn) UpdateRow(ctx context.Context, ref TableRef, key, values map[string]any) (int64, error) {
	if err := checkTableRef(ref); err != nil {
		return 0, err
	}
	if err := checkIdent(ref.Table); err != nil {
		return 0, err
	}
	cols, err := c.ColumnsInfo(ctx, ref)
	if err != nil {
		return 0, err
	}
	pk, err := c.PrimaryKeys(ctx, ref)
	if err != nil || len(pk) == 0 {
		return 0, fmt.Errorf("这张表没有主键，无法安全定位要改的行；请用 SQL 编辑器")
	}

	// SET 部分：主键本身不参与更新
	update := map[string]any{}
	for k, v := range values {
		update[k] = v
	}
	for _, k := range pk {
		delete(update, k)
	}
	setNames, setHolders, setArgs := c.pickValues(cols, update)
	if len(setNames) == 0 {
		return 0, fmt.Errorf("没有要修改的字段")
	}

	where := []string{}
	args := append([]any{}, setArgs...)
	i := len(setArgs) + 1
	for _, k := range pk {
		v, ok := key[k]
		if !ok {
			return 0, fmt.Errorf("缺少主键 %s 的值", k)
		}
		where = append(where, c.quote(k)+" = "+c.placeholder(i))
		args = append(args, v)
		i++
	}

	sets := make([]string, len(setNames))
	for j := range setNames {
		sets[j] = setNames[j] + " = " + setHolders[j]
	}
	q := "UPDATE " + c.qualified(ref) + " SET " + strings.Join(sets, ", ") +
		" WHERE " + strings.Join(where, " AND ")
	r, err := c.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, tidyErr(err)
	}
	n, _ := r.RowsAffected()
	return n, nil
}

// DeleteRows 按主键删除若干行。
func (c *Conn) DeleteRows(ctx context.Context, ref TableRef, keys []map[string]any) (int64, error) {
	if err := checkTableRef(ref); err != nil {
		return 0, err
	}
	if err := checkIdent(ref.Table); err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, fmt.Errorf("没有要删除的行")
	}
	pk, err := c.PrimaryKeys(ctx, ref)
	if err != nil || len(pk) == 0 {
		return 0, fmt.Errorf("这张表没有主键，无法安全删除；请用 SQL 编辑器")
	}

	var args []any
	orParts := []string{}
	n := 1
	for _, key := range keys {
		andParts := []string{}
		for _, k := range pk {
			v, ok := key[k]
			if !ok {
				return 0, fmt.Errorf("缺少主键 %s 的值", k)
			}
			andParts = append(andParts, c.quote(k)+" = "+c.placeholder(n))
			args = append(args, v)
			n++
		}
		orParts = append(orParts, "("+strings.Join(andParts, " AND ")+")")
	}
	q := "DELETE FROM " + c.qualified(ref) + " WHERE " + strings.Join(orParts, " OR ")
	r, err := c.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, tidyErr(err)
	}
	affected, _ := r.RowsAffected()
	return affected, nil
}

// NewColumn 是建表时的字段定义。
type NewColumn struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Nullable   bool   `json:"nullable"`
	PrimaryKey bool   `json:"primary_key"`
	AutoInc    bool   `json:"auto_increment"`
	Default    string `json:"default"`
	Comment    string `json:"comment"`
}

// TableSpec 是建表定义。
type TableSpec struct {
	Database string      `json:"database"`
	Schema   string      `json:"schema"`
	Table    string      `json:"table"`
	Comment  string      `json:"comment"`
	Columns  []NewColumn `json:"columns"`
}

// CreateTable 建表。
func (c *Conn) CreateTable(ctx context.Context, spec TableSpec) error {
	// 库/schema 名以前是唯一漏检的入口：它会被 quote() 包进 CREATE TABLE 的
	// 标识符（`db`.`t`），却只有表名过了 checkIdent。实测 spec.Database 写成
	// `bad"quote` 时请求一路进到 SQL 才报"这张表或这个库不存在"，而 SelectRows /
	// InsertRow / UpdateRow / DeleteRows / ShowCreate 都在入口就明确拒掉了 ——
	// 与它们保持一致，报错也更早更准。
	if err := checkTableRef(TableRef{Database: spec.Database, Schema: spec.Schema, Table: spec.Table}); err != nil {
		return err
	}
	if err := checkIdent(spec.Table); err != nil {
		return fmt.Errorf("表名不合法：%w", err)
	}
	if len(spec.Columns) == 0 {
		return fmt.Errorf("至少要有一个字段")
	}

	defs := []string{}
	pkCols := []string{}
	autoCol := ""
	for _, col := range spec.Columns {
		if err := checkIdent(col.Name); err != nil {
			return fmt.Errorf("字段名不合法：%w", err)
		}
		if err := checkType(col.Type); err != nil {
			return err
		}
		parts := []string{c.quote(col.Name), col.Type}

		if col.AutoInc {
			if c.kind == KindMySQL {
				parts = append(parts, "AUTO_INCREMENT")
			} else {
				if !strings.Contains(strings.ToLower(col.Type), "serial") {
					parts = append(parts, "GENERATED BY DEFAULT AS IDENTITY")
				}
			}
			autoCol = col.Name
		}
		if !col.Nullable {
			parts = append(parts, "NOT NULL")
		}
		if d := strings.TrimSpace(col.Default); d != "" {
			// 数字与函数/关键字原样，其他当字符串字面量
			if isNumericOrKeyword(d) {
				parts = append(parts, "DEFAULT "+d)
			} else {
				parts = append(parts, "DEFAULT '"+escapeString(d)+"'")
			}
		}
		defs = append(defs, strings.Join(parts, " "))
		if col.PrimaryKey {
			pkCols = append(pkCols, c.quote(col.Name))
		}
	}
	_ = autoCol

	if len(pkCols) > 0 {
		defs = append(defs, "PRIMARY KEY ("+strings.Join(pkCols, ", ")+")")
	}

	q := "CREATE TABLE " + c.qualified(TableRef{Database: spec.Database, Schema: spec.Schema, Table: spec.Table}) +
		" (\n  " + strings.Join(defs, ",\n  ") + "\n)"
	if c.kind == KindMySQL && strings.TrimSpace(spec.Comment) != "" {
		q += " COMMENT = '" + escapeString(spec.Comment) + "'"
	}
	if _, err := c.db.ExecContext(ctx, q); err != nil {
		return tidyErr(err)
	}
	return nil
}

func isNumericOrKeyword(s string) bool {
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "NULL", "CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME",
		"NOW()", "TRUE", "FALSE", "GEN_RANDOM_UUID()":
		return true
	}
	return false
}

// ShowCreate 返回建表语句（MySQL 用 SHOW CREATE TABLE，PG 用 pg_get_tabledef 的替代拼装）。
func (c *Conn) ShowCreate(ctx context.Context, ref TableRef) (string, error) {
	if err := checkTableRef(ref); err != nil {
		return "", err
	}
	if err := checkIdent(ref.Table); err != nil {
		return "", err
	}
	if c.kind == KindMySQL {
		var name, ddl string
		if err := c.db.QueryRowContext(ctx, "SHOW CREATE TABLE "+c.qualified(ref)).Scan(&name, &ddl); err != nil {
			return "", tidyErr(err)
		}
		return ddl, nil
	}
	// PostgreSQL：用 pg_catalog 拼一个可读的结构摘要
	cols, err := c.ColumnsInfo(ctx, ref)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("CREATE TABLE " + c.qualified(ref) + " (\n")
	for i, col := range cols {
		line := "  " + c.quote(col.Name) + " " + col.Type
		if !col.Nullable {
			line += " NOT NULL"
		}
		if col.Default != "" {
			line += " DEFAULT " + col.Default
		}
		if i < len(cols)-1 {
			line += ","
		}
		b.WriteString(line + "\n")
	}
	if pk, _ := c.PrimaryKeys(ctx, ref); len(pk) > 0 {
		quoted := make([]string, len(pk))
		for i, k := range pk {
			quoted[i] = c.quote(k)
		}
		b.WriteString("  , PRIMARY KEY (" + strings.Join(quoted, ", ") + ")\n")
	}
	b.WriteString(")")
	return b.String(), nil
}

// ListDatabasesWithTables 只给图形化界面用：一次拿库与表，省得来回跑。
func (c *Conn) ListDatabasesWithTables(ctx context.Context) (map[string][]Table, error) {
	dbs, err := c.Databases(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]Table{}
	for _, db := range dbs {
		tables, err := c.Tables(ctx, db)
		if err != nil {
			// 有的库没权限，跳过而不是整体失败
			out[db] = []Table{}
			continue
		}
		out[db] = tables
	}
	return out, nil
}

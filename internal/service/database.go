package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/awdshell/internal/infra/dbx"
	"github.com/guaidao2/awdshell/internal/infra/sshx"
	"github.com/guaidao2/awdshell/internal/secret"
	"github.com/guaidao2/awdshell/internal/store"

	"golang.org/x/crypto/ssh"
)

// 结果集体积上限的**唯一一套**常量。
//
// 以前 5000 / 500 / 1000 / 100 这几个数散在四处各写各的（保存连接、执行查询、
// HTTP 入参、分页浏览），改一处忘了另一处就会出现"配置里能填 5000、实际只给 500"
// 这类对不上的口径。所有夹取点都必须引用这里的名字，不要再写字面量。
const (
	// MaxQueryRows 是单次 SQL 查询最多返回的行数（连接配置里的上限也受它约束）。
	// 前端 max_rows 输入框的 max 与它一致。
	MaxQueryRows = 5000
	// DefaultQueryRows 是连接配置没给上限（或给成了非法值）时的默认行数。
	DefaultQueryRows = 500

	// MaxPageRows 是图形化分页浏览一页最多返回的行数。
	// 与 MaxQueryRows 是两个口径：分页是"翻着看"，查询是"取一批结果"，
	// 所以分页的上限小得多。
	MaxPageRows = 1000
	// DefaultPageRows 是分页浏览一页的默认行数（前端下拉的默认值也是它）。
	DefaultPageRows = 100
)

// clampQueryRows 把连接配置里的行数上限夹进允许区间。
func clampQueryRows(n int) int {
	if n <= 0 || n > MaxQueryRows {
		return DefaultQueryRows
	}
	return n
}

// clampMaxRowsToConn 把请求要的行数夹到"这条连接配置的上限"之内。
//
// 抽成纯函数是为了能直接单测（Query 那条路要真数据库连接）：
// 客户端传的值只能**收小**、不能放大连接配置里的上限。
// 配置上限本身先过一遍统一的那套夹取（它理论上已经被 SaveConn 夹过，
// 但旧库里的坏数据不能让这里算出 >MaxQueryRows 的量）—— 0 尤其危险，
// 驱动会把 0 当"不限"，等于把整表读进内存。
func clampMaxRowsToConn(requested, connLimit int) int {
	connLimit = clampQueryRows(connLimit)
	if requested <= 0 || requested > connLimit {
		requested = connLimit
	}
	return requested
}

// ClampRequestedRows 夹取 HTTP 入参里的 max_rows。
//
// 0（或负数、缺省）表示"按连接配置来"，最终值由 Query 决定；
// 超过 MaxQueryRows 的请求值直接压到上限，不让它进到下游去放大。
func ClampRequestedRows(n int) int {
	if n < 0 {
		return 0
	}
	if n > MaxQueryRows {
		return MaxQueryRows
	}
	return n
}

// DatabaseService 通过目标机已有的 SSH 连接管理数据库。
//
// 数据库一般只监听 127.0.0.1，所以这里不直连，而是用 SSH 连接自己拨号过去；
// 目标机上不需要装 mysql/psql 客户端，也不需要开公网端口。
type DatabaseService struct {
	targets *TargetService
	pool    *sshx.Pool
	store   *store.Store
	vault   *secret.Vault

	mu    sync.Mutex
	conns map[string]*dbx.Conn   // connID -> 已建立的连接池
	locks map[string]*sync.Mutex // connID -> 建连锁，避免并发重复建连
}

// NewDatabaseService 构造服务。
func NewDatabaseService(targets *TargetService, pool *sshx.Pool, st *store.Store, v *secret.Vault) *DatabaseService {
	return &DatabaseService{
		targets: targets, pool: pool, store: st, vault: v,
		conns: map[string]*dbx.Conn{}, locks: map[string]*sync.Mutex{},
	}
}

// DBConnInput 是保存连接配置的入参。
type DBConnInput struct {
	ID       string `json:"id"`
	TargetID string `json:"target_id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Addr     string `json:"addr"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
	ReadOnly *bool  `json:"read_only"`
	MaxRows  int    `json:"max_rows"`
}

// Conns 列出连接配置；密码不在返回值里。
func (s *DatabaseService) Conns(targetID string) ([]store.DBConn, error) {
	return s.store.ListDBConns(targetID)
}

// SaveConn 保存连接配置（密码加密落盘）。
func (s *DatabaseService) SaveConn(in DBConnInput) (store.DBConn, error) {
	if strings.TrimSpace(in.TargetID) == "" {
		return store.DBConn{}, fmt.Errorf("请先选择目标")
	}
	if strings.TrimSpace(in.Name) == "" {
		return store.DBConn{}, fmt.Errorf("给这条连接起个名字")
	}
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if kind != dbx.KindMySQL && kind != dbx.KindPostgres {
		return store.DBConn{}, fmt.Errorf("数据库类型只能是 mysql 或 postgres")
	}
	addr := strings.TrimSpace(in.Addr)
	if addr == "" {
		// 给个符合直觉的默认值：数据库在目标机本地
		if kind == dbx.KindMySQL {
			addr = "127.0.0.1:3306"
		} else {
			addr = "127.0.0.1:5432"
		}
	}
	if !strings.Contains(addr, ":") {
		if kind == dbx.KindMySQL {
			addr += ":3306"
		} else {
			addr += ":5432"
		}
	}

	c := store.DBConn{
		ID:       strings.TrimSpace(in.ID),
		TargetID: strings.TrimSpace(in.TargetID),
		Name:     strings.TrimSpace(in.Name),
		Kind:     kind,
		Addr:     addr,
		Username: strings.TrimSpace(in.Username),
		Database: strings.TrimSpace(in.Database),
		MaxRows:  in.MaxRows,
		// 默认可写：运维连上数据库本来就是要改东西的，
		// 只读是给"连生产库怕手滑"这类场景留的选项，不该当成默认。
		ReadOnly: false,
	}
	if in.ReadOnly != nil {
		c.ReadOnly = *in.ReadOnly
	}
	// 上限夹取走统一的那一套（见 MaxQueryRows / DefaultQueryRows）：
	// 以前这里写死 5000/500，与执行查询、HTTP 入参、分页浏览的口径各写各的。
	c.MaxRows = clampQueryRows(c.MaxRows)

	// 目标名冗余存一份，列表不用再联表
	if t, _, err := s.targets.Auth(c.TargetID); err == nil {
		c.Target = t.Name
	}

	if c.ID == "" {
		c.ID = newID()
	} else {
		// 编辑已有配置时保留原密文与创建时间。
		// 读失败必须中止保存：硬着头皮写下去会把 secret_id 覆盖成空，
		// 旧密文成孤儿，用户下次连接发现密码没了，而且没有任何提示。
		old, err := s.store.GetDBConn(c.ID)
		if err != nil {
			return c, fmt.Errorf("读取已有配置失败，为避免清掉已保存的密码，这次保存已中止：%w", err)
		}
		c.SecretID = old.SecretID
		c.CreatedAt = old.CreatedAt
	}

	if in.Password != "" {
		if c.SecretID == "" {
			c.SecretID = newID()
		}
		nonce, ct, err := s.vault.Seal(c.SecretID, []byte(in.Password))
		if err != nil {
			return c, fmt.Errorf("加密密码失败: %w", err)
		}
		if err := s.store.PutSecret(c.SecretID, nonce, ct); err != nil {
			return c, fmt.Errorf("保存密码失败: %w", err)
		}
	}

	saved, err := s.store.SaveDBConn(c)
	if err != nil {
		return saved, err
	}
	// 配置变了，扔掉旧连接
	s.dropConn(saved.ID)
	return saved, nil
}

// DeleteConn 删除连接配置。
func (s *DatabaseService) DeleteConn(id string) error {
	s.dropConn(id)
	return s.store.DeleteDBConn(id)
}

// Password 取出解密后的密码。
func (s *DatabaseService) Password(id string) (string, error) {
	c, err := s.store.GetDBConn(id)
	if err != nil {
		return "", fmt.Errorf("找不到这条连接配置")
	}
	if c.SecretID == "" {
		return "", nil
	}
	nonce, ct, err := s.store.GetSecret(c.SecretID)
	if err != nil {
		return "", fmt.Errorf("读不到已保存的密码: %w", err)
	}
	raw, err := s.vault.Open(c.SecretID, nonce, ct)
	if err != nil {
		return "", fmt.Errorf("解密密码失败: %w", err)
	}
	return string(raw), nil
}

// tunnel 用目标机已有的 SSH 连接拨号到数据库端口。
func (s *DatabaseService) tunnel(targetID string) (func(context.Context, string, string) (net.Conn, error), error) {
	target, auth, err := s.targets.Auth(targetID)
	if err != nil {
		return nil, err
	}
	key := poolKey(targetID)
	client, err := s.pool.Acquire(key, func() (*ssh.Client, error) {
		return sshx.Dial(target.Host, target.Port, auth, 12*time.Second)
	})
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		type result struct {
			conn net.Conn
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			// client.Dial 不支持取消，用 goroutine + select 兜住 context
			c, err := client.Dial(network, addr)
			ch <- result{c, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				// 连不上通常是数据库没启动或端口不对；连接池本身没坏，不要 Drop
				return nil, fmt.Errorf("通过 SSH 连目标机的 %s 失败: %w", addr, r.err)
			}
			return r.conn, nil
		case <-ctx.Done():
			// 不能就这么走：goroutine 还在跑，等它拿到连接时会塞进带缓冲的 ch，
			// 而这里已经没人读了 —— 那条连接（共享 SSH 上的一个通道）就永远漏着。
			// 每超时一次漏一个，最后会把这条 SSH 连接的通道上限耗光，
			// 用户正在用的终端也会跟着起不来。
			go func() {
				if r := <-ch; r.conn != nil {
					_ = r.conn.Close()
				}
			}()
			return nil, ctx.Err()
		}
	}, nil
}

// conn 取（或建立）某条配置对应的数据库连接池。
func (s *DatabaseService) conn(id string) (*dbx.Conn, store.DBConn, error) {
	c, err := s.store.GetDBConn(id)
	if err != nil {
		return nil, c, fmt.Errorf("找不到这条连接配置")
	}

	s.mu.Lock()
	if existing, ok := s.conns[id]; ok {
		s.mu.Unlock()
		return existing, c, nil
	}
	lk := s.locks[id]
	if lk == nil {
		lk = &sync.Mutex{}
		s.locks[id] = lk
	}
	s.mu.Unlock()

	// 同一个 id 只允许一个 goroutine 建连。
	// 并发建连会各建一条、后写的覆盖先写的，被覆盖的那条永远没人 Close，
	// 它底下的 sql.DB 与 SSH 隧道通道就一直挂着（SSH 连接是终端共用的）。
	lk.Lock()
	defer lk.Unlock()

	s.mu.Lock()
	if existing, ok := s.conns[id]; ok {
		s.mu.Unlock()
		return existing, c, nil
	}
	s.mu.Unlock()

	pass, err := s.Password(id)
	if err != nil {
		return nil, c, err
	}
	dial, err := s.tunnel(c.TargetID)
	if err != nil {
		return nil, c, err
	}

	conn, err := dbx.Open(dbx.Options{
		Kind: c.Kind, Addr: c.Addr, User: c.Username, Password: pass, Database: c.Database,
		ReadOnly: c.ReadOnly, Dial: dial,
	})
	if err != nil {
		return nil, c, err
	}

	s.mu.Lock()
	// 再查一次：万一别的路径（比如 dropConn）在这期间动过
	if existing, ok := s.conns[id]; ok {
		s.mu.Unlock()
		_ = conn.Close()
		return existing, c, nil
	}
	s.conns[id] = conn
	s.mu.Unlock()
	return conn, c, nil
}

func (s *DatabaseService) dropConn(id string) {
	s.mu.Lock()
	existing := s.conns[id]
	delete(s.conns, id)
	delete(s.locks, id)
	s.mu.Unlock()
	if existing != nil {
		_ = existing.Close()
	}
}

// DropConnsOfTarget 关掉并移除某个目标下的**全部**数据库连接池。
//
// 删目标时必须调它。conns 是"connID → 已建立的连接池"，只删配置不清缓存的话，
// dbx.Conn 还活着、SSH 隧道还开着，`/api/db/query` 仍能对着已删目标走通
// （实测删完目标后缓存里仍有 1 条）。
func (s *DatabaseService) DropConnsOfTarget(targetID string) {
	if targetID == "" {
		return
	}
	list, err := s.store.ListDBConns(targetID)
	if err != nil {
		return // 配置都读不到，也没什么可清的
	}
	for _, c := range list {
		s.dropConn(c.ID)
	}
}

// CloseAll 关闭全部数据库连接（退出时调用）。
func (s *DatabaseService) CloseAll() {
	s.mu.Lock()
	list := make([]*dbx.Conn, 0, len(s.conns))
	for _, c := range s.conns {
		list = append(list, c)
	}
	s.conns = map[string]*dbx.Conn{}
	s.mu.Unlock()
	for _, c := range list {
		_ = c.Close()
	}
}

// Test 试连一次（用入参而不是已保存的配置，方便保存前先验证）。
func (s *DatabaseService) Test(in DBConnInput) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	if kind != dbx.KindMySQL && kind != dbx.KindPostgres {
		return "", fmt.Errorf("请选择数据库类型")
	}
	addr := strings.TrimSpace(in.Addr)
	if addr == "" {
		if kind == dbx.KindMySQL {
			addr = "127.0.0.1:3306"
		} else {
			addr = "127.0.0.1:5432"
		}
	}
	if !strings.Contains(addr, ":") {
		if kind == dbx.KindMySQL {
			addr += ":3306"
		} else {
			addr += ":5432"
		}
	}

	// 密码留空且是在编辑已有配置时，用存下来的那个
	pass := in.Password
	if pass == "" && in.ID != "" {
		if p, err := s.Password(in.ID); err == nil {
			pass = p
		}
	}

	dial, err := s.tunnel(in.TargetID)
	if err != nil {
		return "", err
	}
	conn, err := dbx.Open(dbx.Options{
		Kind: kind, Addr: addr, User: in.Username, Password: pass, Database: in.Database,
		Dial: dial,
	})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := conn.Ping(ctx); err != nil {
		return "", err
	}
	label := "MySQL"
	if kind == dbx.KindPostgres {
		label = "PostgreSQL"
	}
	return fmt.Sprintf("%s 连接正常（%s）", label, addr), nil
}

// Query 执行一条 SQL。
func (s *DatabaseService) Query(id, sqlText string, maxRows int) (*dbx.Result, error) {
	conn, c, err := s.conn(id)
	if err != nil {
		return nil, err
	}
	// 按连接的**方言**判只读：`\'` 在 MySQL 默认 sql_mode 下是字面量里的转义引号，
	// 一律按"有分隔符"判会把 `SELECT 'it\'s'` 这种普通查询误判成写（只读连接被拒、
	// 非只读连接走 Exec 把结果集丢掉）。PG 那边反过来没有反斜杠转义，保守判才安全。
	if c.ReadOnly && !dbx.IsReadOnlySQLFor(sqlText, c.Kind) {
		return nil, fmt.Errorf("这条连接是只读模式，只允许查询类语句（SELECT / SHOW / EXPLAIN 等）。要执行写操作，请在编辑连接时取消「只读」")
	}
	// 客户端传的值不能放大连接配置里的上限（夹取的口径见 clampMaxRowsToConn）
	maxRows = clampMaxRowsToConn(maxRows, c.MaxRows)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := conn.Query(ctx, sqlText, maxRows)
	if err != nil {
		// 这里不能复用 sshx.IsConnError：那是给 RunOutput 用的判据，
		// 对数据库驱动错误恒为真，会让"SQL 写错一次"就拆掉整条连接
		// （并影响并发中的其他查询）。database/sql 自己会丢弃坏连接。
		return nil, err
	}
	return res, nil
}

// Databases 列出可访问的库。
func (s *DatabaseService) Databases(id string) ([]string, error) {
	conn, _, err := s.conn(id)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := conn.Databases(ctx)
	if err != nil {
		// 元数据查询轻量、无副作用，出错多半是隧道死了（比如 SSH 连接被空闲回收），
		// 清掉缓存下次重建；不清的话库/表树会一直刷不出来。
		s.dropConn(id)
	}
	return out, err
}

// Tables 列出某个库里的表与视图。
func (s *DatabaseService) Tables(id, dbName string) ([]dbx.Table, error) {
	conn, _, err := s.conn(id)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := conn.Tables(ctx, dbName)
	if err != nil {
		s.dropConn(id)
	}
	return out, err
}

// Columns 列出某张表的字段（带主键标记，图形化与结构页都用它）。
func (s *DatabaseService) Columns(id, dbName, schema, table string) ([]dbx.ColumnInfo, error) {
	conn, _, err := s.conn(id)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := conn.ColumnsInfo(ctx, dbx.TableRef{Database: dbName, Schema: schema, Table: table})
	if err != nil {
		s.dropConn(id)
	}
	return out, err
}

// ---------- 图形化操作 ----------

// Rows 分页读一张表的数据。
//
// 筛选条件是这条路上唯一的"用户自己写的表达式"，它会原样拼进 WHERE。
// 只读连接下要额外收一道：否则可以借 UNION 读别的表/库，
// 或者用 INTO OUTFILE 这类语法在目标机落文件，而用户以为自己只是"筛了个条件"。
// 真正的边界仍在服务端的只读事务，这里只是别让只读模式名不副实。
func (s *DatabaseService) Rows(id string, ref dbx.TableRef, rq dbx.RowQuery) (*dbx.RowPage, error) {
	conn, c, err := s.conn(id)
	if err != nil {
		return nil, err
	}
	if c.ReadOnly && strings.TrimSpace(rq.Filter) != "" {
		if err := checkFilterForReadOnly(rq.Filter); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	page, err := conn.SelectRows(ctx, ref, rq)
	if err != nil {
		// 不 dropConn：database/sql 自己会丢弃坏连接，
		// 而这里拿到的错误已经被 tidyErr 改写成中文，没法再判断是
		// "语句写错"还是"连接断了" —— 误判会顺手 Close 掉连接池，
		// 让并发的结构页请求报 "sql: database is closed"。
		return nil, err
	}
	return page, nil
}

// checkFilterForReadOnly 在只读连接上限制筛选条件能写什么。
//
// 正常的筛选（id > 10、name LIKE '%a%'、a = 1 AND b < 2）一律放行；
// 只拦那些"借筛选之名做别的事"的写法。
func checkFilterForReadOnly(filter string) error {
	low := strings.ToLower(filter)
	for _, bad := range []string{
		";", "union", "into outfile", "into dumpfile",
		"insert", "update", "delete", "drop", "create", "alter", "grant", "truncate",
	} {
		if strings.Contains(low, bad) {
			return fmt.Errorf("这条连接是只读模式，筛选条件里不能出现 %s。"+
				"要写复杂查询请在「SQL」标签里操作，或取消该连接的只读模式", bad)
		}
	}
	return nil
}

// InsertRow 插入一行。
func (s *DatabaseService) InsertRow(id string, ref dbx.TableRef, values map[string]any) (int64, error) {
	return s.writeRow(id, func(ctx context.Context, conn *dbx.Conn) (int64, error) {
		return conn.InsertRow(ctx, ref, values)
	})
}

// UpdateRow 按主键更新一行。
func (s *DatabaseService) UpdateRow(id string, ref dbx.TableRef, key, values map[string]any) (int64, error) {
	return s.writeRow(id, func(ctx context.Context, conn *dbx.Conn) (int64, error) {
		return conn.UpdateRow(ctx, ref, key, values)
	})
}

// DeleteRows 按主键删除若干行。
func (s *DatabaseService) DeleteRows(id string, ref dbx.TableRef, keys []map[string]any) (int64, error) {
	return s.writeRow(id, func(ctx context.Context, conn *dbx.Conn) (int64, error) {
		return conn.DeleteRows(ctx, ref, keys)
	})
}

func (s *DatabaseService) writeRow(id string, fn func(context.Context, *dbx.Conn) (int64, error)) (int64, error) {
	conn, c, err := s.conn(id)
	if err != nil {
		return 0, err
	}
	if c.ReadOnly {
		return 0, fmt.Errorf("这条连接是只读模式，不能改数据；要写入请在编辑连接时取消「只读」")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return fn(ctx, conn)
}

// ShowCreate 取建表语句。
func (s *DatabaseService) ShowCreate(id string, ref dbx.TableRef) (string, error) {
	conn, _, err := s.conn(id)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return conn.ShowCreate(ctx, ref)
}

// CreateTable 建表。
func (s *DatabaseService) CreateTable(id string, spec dbx.TableSpec) error {
	conn, c, err := s.conn(id)
	if err != nil {
		return err
	}
	if c.ReadOnly {
		return fmt.Errorf("这条连接是只读模式，不能建表；要写入请在编辑连接时取消「只读」")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return conn.CreateTable(ctx, spec)
}

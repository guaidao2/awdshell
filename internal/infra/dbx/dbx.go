// Package dbx 通过已有的 SSH 连接访问目标机上的数据库。
//
// 两条设计原则：
//
//  1. 不往目标机装任何东西。数据库通常只监听 127.0.0.1，这里用 SSH 连接自己
//     Dial 出隧道，再用纯 Go 驱动直连 —— 所以目标机上连 mysql/psql 客户端都不需要。
//  2. 只依赖纯 Go 驱动（go-sql-driver/mysql 与 pgx），构建时不开 CGO，
//     保持单二进制交付。
package dbx

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// 支持的数据库类型
const (
	KindMySQL    = "mysql"
	KindPostgres = "postgres"
)

// Options 建立一条数据库连接需要的参数。
type Options struct {
	Kind     string
	Addr     string // 目标机视角的地址，例如 127.0.0.1:5432
	User     string
	Password string
	Database string
	// ReadOnly 为真时，在**服务器端**把会话设成只读事务，
	// 由数据库自己拒绝写操作。客户端的前缀正则只能当友好提示，拦不住
	// `WITH ... DELETE`、`EXPLAIN ANALYZE DELETE`、`SELECT ... INTO OUTFILE` 这类语句。
	ReadOnly bool
	// Dial 由调用方提供（走 SSH 连接）。network/addr 是目标机视角的地址。
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Conn 是一条数据库连接。
type Conn struct {
	kind string
	db   *sql.DB
}

// Kind 返回数据库类型。
func (c *Conn) Kind() string { return c.kind }

// Close 关闭连接。
func (c *Conn) Close() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Close()
}

// Open 建立连接（此时并不握手，Ping 才会真正连过去）。
func Open(opt Options) (*Conn, error) {
	if opt.Dial == nil {
		return nil, fmt.Errorf("缺少 SSH 隧道")
	}
	if strings.TrimSpace(opt.Addr) == "" {
		return nil, fmt.Errorf("缺少数据库地址")
	}
	switch opt.Kind {
	case KindMySQL:
		return openMySQL(opt)
	case KindPostgres:
		return openPostgres(opt)
	}
	return nil, fmt.Errorf("暂不支持这个数据库类型：%s", opt.Kind)
}

// sshChanConn 包住 SSH 通道返回的连接。
//
// 为什么必须包：go-sql-driver/mysql 在握手与每次读写都会调用 SetDeadline，
// 而 SSH 通道的 net.Conn 不支持 deadline，会返回
// "ssh: tcpChan: deadline not supported"；驱动一收到这个错误就把连接判为失效，
// 报成 "invalid connection"。表现就是 MySQL/MariaDB 怎么都连不上。
//
// 这里自己实现 deadline：到期直接关闭底层连接（等价于超时中断）。
// 这样既消掉了驱动的报错，又保留了超时能力。
type sshChanConn struct {
	net.Conn
	mu    sync.Mutex
	timer *time.Timer
}

func (c *sshChanConn) armDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if t.IsZero() {
		return nil
	}
	d := time.Until(t)
	if d <= 0 {
		return os.ErrDeadlineExceeded
	}
	c.timer = time.AfterFunc(d, func() { _ = c.Conn.Close() })
	return nil
}

func (c *sshChanConn) SetDeadline(t time.Time) error      { return c.armDeadline(t) }
func (c *sshChanConn) SetReadDeadline(t time.Time) error  { return c.armDeadline(t) }
func (c *sshChanConn) SetWriteDeadline(t time.Time) error { return c.armDeadline(t) }

// tunnelDial 把底层隧道拨号结果包一层，供驱动使用。
func tunnelDial(dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &sshChanConn{Conn: c}, nil
	}
}

func openMySQL(opt Options) (*Conn, error) {
	cfg := mysql.NewConfig()
	cfg.User = opt.User
	cfg.Passwd = opt.Password
	cfg.DBName = opt.Database
	cfg.Addr = opt.Addr
	cfg.Timeout = 8 * time.Second
	cfg.ReadTimeout = 120 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	cfg.ParseTime = true
	cfg.AllowNativePasswords = true
	// InterpolateParams=true 由客户端把参数拼进 SQL 文本（少一次往返），它的安全性
	// 依赖驱动的 unsafeCollations 护栏 —— 而那个护栏**只在 Collation != "" 时生效**。
	// 这里不设 Charset/Collation，握手固定 utf8mb4_general_ci（在驱动内置的
	// unsafeCollations 表里），所以按当前配置是安全的。
	//
	// **以后要开放 charset/collation 选项，必须同时把 InterpolateParams 关掉**：
	// 用户选到 gbk 之类多字节编码时，驱动的护栏靠 Collation 触发，一旦 Collation
	// 为空它就默认放行，宽字节字符能吃掉后面的单引号、把参数拼成注入。
	cfg.InterpolateParams = true

	if opt.ReadOnly {
		// 交给服务器兜底：这个会话开只读事务，写操作会被数据库直接拒掉
		cfg.Params = map[string]string{"transaction_read_only": "1"}
	}

	// 用 Config.DialFunc 而不是全局的 RegisterDialContext：
	// 后者注册进的是包级表、只有 Deregister 才能删，而闭包会捕获整份 opt
	// （含明文口令），等于每建一次连接就往全局留一份口令，直到进程退出。
	wrapped := tunnelDial(opt.Dial)
	addr := opt.Addr
	cfg.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		return wrapped(ctx, "tcp", addr)
	}

	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("构造 MySQL 连接失败: %w", err)
	}
	return &Conn{kind: KindMySQL, db: sql.OpenDB(connector)}, nil
}

func openPostgres(opt Options) (*Conn, error) {
	dbName := strings.TrimSpace(opt.Database)
	if dbName == "" {
		dbName = strings.TrimSpace(opt.User) // PG 默认库名与用户名相同
	}
	// 用 URL 形式组装，用户名/密码里的特殊字符由 url 包负责转义
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(opt.User, opt.Password),
		Host:   opt.Addr,
		Path:   "/" + dbName,
	}
	q := u.Query()
	q.Set("sslmode", "prefer")
	q.Set("connect_timeout", "8")
	u.RawQuery = q.Encode()

	cfg, err := pgx.ParseConfig(u.String())
	if err != nil {
		return nil, fmt.Errorf("构造 PostgreSQL 连接失败: %w", err)
	}
	if opt.ReadOnly {
		// 交给服务器兜底：默认只读事务，写操作会被数据库直接拒掉
		if cfg.RuntimeParams == nil {
			cfg.RuntimeParams = map[string]string{}
		}
		cfg.RuntimeParams["default_transaction_read_only"] = "on"
	}
	// 所有网络连接都走 SSH 隧道；同样包一层，兼容需要 deadline 的调用
	cfg.DialFunc = tunnelDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return opt.Dial(ctx, "tcp", opt.Addr)
	})
	return &Conn{kind: KindPostgres, db: stdlib.OpenDB(*cfg)}, nil
}

// Ping 试连一次。
func (c *Conn) Ping(ctx context.Context) error {
	if c == nil || c.db == nil {
		return fmt.Errorf("连接未建立")
	}
	if err := c.db.PingContext(ctx); err != nil {
		return tidyErr(err)
	}
	return nil
}

// tidyErr 把驱动的原始错误整理成人能看懂的一句话。
// 注意统一转小写再比对：MySQL 报的是 "Unknown database"（大写 U），
// Go 的网络错误是 "connection refused"（小写），Windows 上还会出现
// "connectex: No connection could be made because the target machine actively refused it"。
func tidyErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "access denied"),
		strings.Contains(low, "password authentication failed"):
		return fmt.Errorf("认证失败：用户名或密码不对")
	case strings.Contains(low, "unknown database"),
		strings.Contains(low, "does not exist"),
		strings.Contains(low, "doesn't exist"),
		strings.Contains(low, "doesnt exist"):
		return fmt.Errorf("这张表或这个库不存在")
	case strings.Contains(low, "connection refused"),
		strings.Contains(low, "connect failed"),
		strings.Contains(low, "actively refused"),
		strings.Contains(low, "connectex"):
		return fmt.Errorf("目标机上没有服务在监听这个端口（数据库没启动，或地址填错了）")
	case strings.Contains(low, "i/o timeout"),
		strings.Contains(low, "context deadline exceeded"):
		return fmt.Errorf("连接超时：数据库可能没在监听，或防火墙拦了")
	case strings.Contains(low, "no such host"):
		return fmt.Errorf("找不到这个主机名")
	case strings.Contains(msg, "通过 SSH 连目标机"):
		// 隧道层的说明已经够清楚了，去掉驱动重复包装的那一长串
		if i := strings.Index(msg, "通过 SSH 连目标机"); i >= 0 {
			return fmt.Errorf("%s", strings.TrimSpace(msg[i:]))
		}
	}
	return err
}

// ---------- 结果与元数据 ----------

// Result 是一条 SQL 的执行结果。
type Result struct {
	Statement string     `json:"statement"`
	Columns   []string   `json:"columns"`
	Rows      [][]string `json:"rows"`
	RowCount  int        `json:"row_count"`
	Affected  int64      `json:"affected"`
	ElapsedMs int64      `json:"elapsed_ms"`
	Truncated bool       `json:"truncated"`
	ReadOnly  bool       `json:"read_only"`
}

// readOnlyRe 是只读语句的第一道（友好提示用）。
//
// 真正兜底的是服务器端的只读事务（见 Options.ReadOnly）：
// 纯客户端正则拦不住 `WITH ... DELETE`、`EXPLAIN ANALYZE DELETE`、
// `SELECT ... INTO OUTFILE` 这类"看着像查询、语义上会写"的语句。
var readOnlyRe = regexp.MustCompile(`(?is)^(select|show|describe|desc|explain|table|values|pragma)\b`)

// stmtRe 用来确认 EXPLAIN 后面剩下的确实是一条语句（而不是没认出来的修饰语）。
var stmtRe = regexp.MustCompile(`(?is)^(select|insert|update|delete|merge|truncate|with|table|values|show|describe|desc|explain|create|drop|alter|grant|revoke)\b`)

// flattenSQL 把 SQL 压平，供关键字匹配用。
//
// 为什么要压平：
//   - `INTO  OUTFILE`（多空格）、`INTO\tOUTFILE`、`INTO\nOUTFILE` 这类分隔符变体，
//     字面子串匹配认不出来，但数据库照收，会在目标机落文件；
//   - `INTO/**/OUTFILE` 同理，注释把关键字劈开了；
//   - MySQL 的 `/*! ... */` 与 `/*!50000 ... */` 是**可执行注释**（内容会真的执行），
//     不能当普通注释丢掉 —— 否则 `EXPLAIN /*!50000 ANALYZE */ DELETE FROM t`
//     会被判成只读，而数据库会真的执行那条 DELETE。
//
// 处理规则：普通注释与行注释丢弃，可执行注释保留内容（去掉 /*! 与版本号），
// 连续空白压成一个空格。整体 O(n)，不做反复扫描。
//
// **引号状态机是必须的**：字符串字面量与反引号标识符里的 `#`、`-- `、`/*`
// 都不是注释。以前这里只按字面找标记，于是
// `SELECT '#x' INTO OUTFILE '/tmp/x'` 里的 `#` 被当成行注释，把后半条语句
// 连同真正的写操作整段吞掉，压平后只剩 `SELECT '` —— IsReadOnlySQL 判成
// **只读**，只读连接下把它放行到落文件（审计实测）。同文件的
// hasStatementSeparator / quoteAwareWords 都在跳引号，这里是唯一漏掉的。
func flattenSQL(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	var quote byte // 非 0 表示正处在 ' / " / ` 里面
	for i := 0; i < len(s); {
		c := s[i]

		if quote != 0 {
			b.WriteByte(c)
			if c == '\\' && quote != '`' {
				// MySQL 的反斜杠转义：下一个字节也属于这个字面量，
				// 不能让它被当成引号结束。
				if i+1 < len(s) {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
			} else if c == quote {
				// 两个连写的引号代表一个引号本身（SQL 标准）
				if i+1 < len(s) && s[i+1] == quote {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				quote = 0
			}
			i++
			continue
		}

		switch c {
		case '\'', '"', '`':
			quote = c
			b.WriteByte(c)
			i++
			continue
		case '#':
			// 到行尾的注释（MySQL/MariaDB）
			if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
				i += j + 1
				b.WriteByte(' ')
				continue
			}
			i = len(s)
			continue
		}

		if strings.HasPrefix(s[i:], "/*") {
			executable := strings.HasPrefix(s[i:], "/*!")
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				// 注释没闭合：剩余内容原样保留，交给上层判
				b.WriteString(s[i:])
				break
			}
			if executable {
				inner := s[i+3 : i+2+end]
				inner = strings.TrimLeft(inner, "0123456789") // /*!50000 ... */
				b.WriteByte(' ')
				b.WriteString(inner)
				b.WriteByte(' ')
			} else {
				b.WriteByte(' ')
			}
			i += 2 + end + 2
			continue
		}
		// 行注释：`--` 后必须跟空白（或到行尾）才算注释，避免误伤 a--b
		if strings.HasPrefix(s[i:], "--") {
			rest := s[i+2:]
			if rest == "" || rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\n' || rest[0] == '\r' {
				if j := strings.IndexByte(s[i:], '\n'); j >= 0 {
					i += j + 1
					// **必须补一个空格**：不补的话 `INTO--\nOUTFILE` 会被粘成
					// `intooutfile`，后面判 `into outfile` 就落空。
					b.WriteByte(' ')
					continue
				}
				break
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// hasStatementSeparator 判断有没有"真正在语句之间的"分号（**方言不明**的口径）。
//
// 字符串字面量（'...' / "..."）与反引号标识符里的分号不算 —— `SELECT 'a;b'`
// 是一条普通查询，以前被当成多语句后走 ExecContext，结果集被静默丢掉，
// 界面显示"无结果 / 影响 0 行"。注释在 flattenSQL 里已经处理掉了。
//
// 方言不明时按最保守的方向：把 `\` 当普通字符（见 hasStatementSeparatorIn）。
func hasStatementSeparator(sqlText string) bool {
	return hasStatementSeparatorIn(sqlText, false)
}

// hasStatementSeparatorIn 是带方言参数的实现。
//
// backslashEscapes 为真表示"这个方言里 `\` 是字符串字面量内的转义符"
// （MySQL / MariaDB 默认 sql_mode；不含 NO_BACKSLASH_ESCAPES）。
//
// **为什么必须分方言**（复审 高1）：MySQL 里 `SELECT 'it\'s' AS c` 与
// `WHERE name='O\'Brien'` 都是最普通的写法，而"`\` 后面跟引号 → 判有分隔符"
// 的保守口径把它们判成**写**，两条后果都很实在：
//   - 只读连接上直接被拒（"只允许查询类语句"）；
//   - 非只读连接上走 ExecContext，**SELECT 的结果集被静默丢掉**，
//     界面显示"影响 0 行" —— 正是这一轮要消灭的那类静默丢结果。
//
// 反过来，PG / SQLite 里 `\` 是普通字符，`SELECT 'a\';DROP TABLE t` 真的是
// **两条语句**；按 MySQL 口径跳过后整串会被当成"未闭合的字符串"，判成只读 →
// 走 QueryContext、多语句闸门形同不存在。所以：
//
//	MySQL  → backslashEscapes = true（按转义语义）
//	其余/未知 → false（宁可判"有分隔符"拒只读，也不漏）
func hasStatementSeparatorIn(sqlText string, backslashEscapes bool) bool {
	var quote byte
	for i := 0; i < len(sqlText); i++ {
		c := sqlText[i]
		if quote != 0 {
			if c == '\\' && quote != '`' {
				if !backslashEscapes && i+1 < len(sqlText) && sqlText[i+1] == quote {
					// 非 MySQL：`\` 不转义，这个引号就是字面量的结尾，
					// 后面紧跟的东西有可能已经是新语句的一部分 —— 保守拒只读。
					return true
				}
				// 跳过被转义（或本方言里无特殊含义）的那一个字节：
				// MySQL 下必须跳，否则 `\'` 里的引号会被当成字面量结尾。
				i++
				continue
			}
			if c == quote {
				if i+1 < len(sqlText) && sqlText[i+1] == quote {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			quote = c
		case ';':
			return true
		}
	}
	return false
}

// wordsOnly 把非字母数字一律压成空格，用于判"单词序列"。
// 与 flattenSQL 的区别：那个保留标点（多语句判据要用 `;`），这个抹掉标点。
func wordsOnly(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteByte(c)
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

// containsWordPair 判断两个单词是否**相邻**出现（中间只隔空白）。
// 用 Fields 切开逐词比，所以 `xinto outfile` 这种粘词不会误命中。
func containsWordPair(s, a, b string) bool {
	f := strings.Fields(s)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == a && f[i+1] == b {
			return true
		}
	}
	return false
}

// containsWord 判断某个单词是否作为一个**独立词**出现。
func containsWord(s, w string) bool {
	for _, f := range strings.Fields(s) {
		if f == w {
			return true
		}
	}
	return false
}

// containsWordTriple 判断三个单词是否**按顺序相邻**出现（中间只隔空白）。
// 用来认 `NEXT VALUE FOR myseq` 这种词组形态的副作用（它不是函数调用形态，
// 没有括号，containsWord 那种逐词判据认不出"这三个词连在一起"）。
func containsWordTriple(s, a, b, c string) bool {
	f := strings.Fields(s)
	for i := 0; i+2 < len(f); i++ {
		if f[i] == a && f[i+1] == b && f[i+2] == c {
			return true
		}
	}
	return false
}

// trimTrailingSemicolons 削掉尾部连续的 `;` 与空白。
//
// 为什么要抽成一个函数（审计 第 10 条）：只读判定与真正发出去的语句必须
// **用同一套口径**。以前判定侧用 TrimRight(s, "; ")（削掉全部尾部分号）、
// 发送侧用 TrimSuffix(s, ";")（只削一个），于是 `SELECT 1;;` 被判成只读，
// 却把 `SELECT 1;;` 原样发给 MySQL —— 语法错。
// 注：只处理**尾部**，语句中间的分号是 hasStatementSeparator 的事（它跳引号）。
func trimTrailingSemicolons(s string) string {
	for {
		t := strings.TrimRight(s, " \t\r\n")
		if !strings.HasSuffix(t, ";") {
			return t
		}
		s = t[:len(t)-1]
	}
}

// selectIntoTable 判断是否存在 `into <标识符>` 形态
// （PG 的 CREATE TABLE AS、MySQL 的变量赋值）。outfile/dumpfile 由调用方单独处理。
//
// words 是压平后的文本：`@a` 里的 `@` 已被抹成空格，所以 `SELECT 1 INTO @a`
// 会变成 `... into a`，这里也能命中。
func selectIntoTable(sqlText string) bool {
	return selectIntoTableIn(sqlText, false)
}

// selectIntoTableIn 是带方言参数的版本（反斜杠转义见 quoteAwareWordsIn）。
func selectIntoTableIn(sqlText string, backslashEscapes bool) bool {
	f := quoteAwareWordsIn(sqlText, backslashEscapes)
	for i := 0; i+1 < len(f); i++ {
		if f[i] != "into" {
			continue
		}
		switch f[i+1] {
		case "outfile", "dumpfile":
			continue
		}
		return true
	}
	return false
}

// quoteAwareWords 按"SQL 词"切分，但**跳过字符串字面量与反引号标识符内部** ——
// 那里的内容不是关键字（`SELECT 'into outfile' AS note` 是普通查询）。
// 标点一律当分隔符，所以 `INTO/**/OUTFILE` 这类也能切开。
//
// 保守默认：`\` 不当转义（见 quoteAwareWordsIn）。
func quoteAwareWords(s string) []string {
	return quoteAwareWordsIn(s, false)
}

// quoteAwareWordsIn 带方言参数：backslashEscapes 为真时 `\'` 是**字面量里的引号**，
// 不是字面量的结尾。
//
// 为什么这里也必须分方言（复审 高1 的同一条）：MySQL 下
// `SELECT 'a\'b' INTO OUTFILE '/tmp/x'` 的字面量是 `a'b`，后面那句 INTO OUTFILE
// 是真的写操作。本函数以前不认反斜杠，于是把 `\'` 当成字面量结尾，后面的内容被
// 切成一堆碎片 —— 分词结果里再也凑不出 `into outfile`，这条**会落文件的语句
// 反而被判成只读**。以前它"看起来是对的"只是因为 hasStatementSeparator 那条
// 过宽的判据替它兜住了（一律判写），而那条判据正是高1 要修的。
func quoteAwareWordsIn(s string, backslashEscapes bool) []string {
	var out []string
	var b strings.Builder
	var quote byte
	flush := func() {
		if b.Len() > 0 {
			out = append(out, strings.ToLower(b.String()))
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' && quote != '`' && backslashEscapes {
				i++ // 跳过被转义的字节（`\'` 不是字面量结尾）
				continue
			}
			if c == quote {
				if i+1 < len(s) && s[i+1] == quote {
					i++
					continue
				}
				quote = 0
			}
			continue
		}
		switch {
		case c == '\'' || c == '"' || c == '`':
			quote = c
			flush()
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			flush()
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_':
			b.WriteByte(c)
		default:
			flush()
		}
	}
	flush()
	return out
}

// IsReadOnlySQL 判断一条语句是不是只读的（查询类），**方言不明**的口径。
//
// 用来决定走 Query 还是 Exec，也用来提前给出"只读模式"的友好提示。
// 注意它**不是**安全边界，安全边界在数据库那边。
//
// 方言不明的口径是保守的那一侧：`\` 当普通字符 —— 于是 MySQL 的
// `SELECT 'it\'s'` 会被判成写。**调用方知道方言时必须用 IsReadOnlySQLFor**，
// 否则 MySQL 连接上最普通的转义引号写法要么被只读模式拒掉，
// 要么在非只读连接上被判成写、走 ExecContext 把结果集静默丢掉。
// 保留这个签名只为不惊动既有调用方（签名一变就要连带动 service）。
func IsReadOnlySQL(sqlText string) bool {
	return isReadOnlySQL(sqlText, "")
}

// IsReadOnlySQLFor 按**连接方言**判断一条语句是不是只读的。
//
// kind 取 KindMySQL / KindPostgres（空串或未知 = 按最保守口径，等价于
// IsReadOnlySQL）。Conn.Query 内部用的就是这个函数，调用方（service）在
// "只读模式"的前置校验里也应当用它，两处口径才会一致。
func IsReadOnlySQLFor(sqlText, kind string) bool {
	return isReadOnlySQL(sqlText, kind)
}

func isReadOnlySQL(sqlText, kind string) bool {
	// 反斜杠是否转义**只看方言**：MySQL/MariaDB 是转义符，PG 不是。
	backslashEscapes := kind == KindMySQL
	// 先压平，再判。**不能用"剥掉前导注释"的办法**：MySQL 的 `/*!...*/`、
	// `/*!50000 ... */` 是**可执行注释**，服务端会把里面的内容展开执行，而
	// 老实现无条件把它当注释剥掉，于是 `/*!50000 DROP TABLE t */ SELECT 1`
	// 剥成 `SELECT 1` 被判成只读（实测如此）。flattenSQL 对可执行注释是
	// **保留内容**的，与下面所有判据用的是同一套语义，不会再出现两处不一致。
	//
	// 顺带解决前导 `--` 行注释：flattenSQL 里 `--` 后面必须跟空白才算注释。
	s := flattenSQL(sqlText)
	if s == "" {
		return false // 通篇只有注释（或本来就是空的）
	}
	// 前导括号：`(SELECT 1)` 也是纯查询，剥掉再判
	for strings.HasPrefix(s, "(") {
		s = strings.TrimSpace(s[1:])
	}
	if s == "" {
		return false
	}

	low := strings.ToLower(s)
	flat := flattenSQL(low)

	// 多语句一律不当只读：`SELECT 1; DROP TABLE t` 靠前缀正则拦不住。
	// 但先去尾分号 —— `SELECT 1;` 是最普通的写法，一刀切会把只读连接上
	// 正常的查询挡掉（Conn.Query 里已经这么处理了，这道闸门要对齐）。
	//
	// **两处口径必须一模一样**（审计 第 10 条）：这里原来是 TrimRight(flat, "; ")，
	// 把**所有**尾部分号都削掉，于是 `SELECT 1;;` 被判成只读；而 Conn.Query 只
	// TrimSuffix 一次，真正发给数据库的还是 `SELECT 1;;` —— MySQL 下那是语法错。
	// 现在两边都走 trimTrailingSemicolons，判"只读"与"发什么"永远一致。
	//
	// **分号要跳过引号里的**：`SELECT 'a;b'` 的分号在字符串字面量内，不是多语句 ——
	// 以前判成写之后走 ExecContext，**SELECT 的结果集被静默丢掉**，
	// 界面显示"无结果 / 影响 0 行"。那是 hasStatementSeparator 自己的事，
	// 它跳引号；这里只负责"尾部多出来的分号"。
	if hasStatementSeparatorIn(trimTrailingSemicolons(flat), backslashEscapes) {
		return false
	}
	// 这两类会在目标机落文件。**按单词序列判**，不按子串：
	// 把非字母数字一律压成空格之后，任何符号切分（`INTO/**/OUTFILE`、
	// `INTO--\nOUTFILE`、`INTO#\nOUTFILE`、`INTO\tOUTFILE`）都不再有效，
	// 而 `xinto outfile` 这种粘词也不会误命中。
	// 用 quoteAwareWordsIn（**跳过字符串字面量里的内容**）而不是压平后的 wordsOnly：
	// `SELECT 'into outfile' AS note` 是普通查询，压平会把引号抹成空格，
	// 于是它被误判成写 —— 只读模式下把合法查询挡掉、非只读模式下结果集被丢。
	// 分词也必须按方言转义，否则 MySQL 的 `SELECT 'a\'b' INTO OUTFILE '/tmp/x'`
	// 会在这里被切碎、凑不出 into outfile（见 quoteAwareWordsIn）。
	qw := strings.Join(quoteAwareWordsIn(flat, backslashEscapes), " ")
	if containsWordPair(qw, "into", "outfile") || containsWordPair(qw, "into", "dumpfile") {
		return false
	}
	// `SELECT ... INTO <标识符>`：PG 里就是 CREATE TABLE AS（建表），
	// MySQL 里是变量赋值（`SELECT 1 INTO @a`）。outfile/dumpfile 上面已单独判过。
	if selectIntoTableIn(flat, backslashEscapes) {
		return false
	}
	// 会产生**副作用**的函数：只读模式下不该放行。
	// 服务端只读事务能兜住 SELECT INTO / nextval / setval，兜不住
	// pg_terminate_backend 这类"函数动作"（照样能断掉别人的连接）。
	//
	// 审计实测放行的五个（第 9 条），逐个补进来：
	//   SELECT NEXT VALUE FOR myseq      —— 序列推进（SQL 标准写法，
	//                                       不在 nextval 那条判据的覆盖里）
	//   set_config('default_transaction_read_only','off',false) —— 直接把
	//                                       只读会话改成可写（最坏的一个）
	//   lo_put / pg_stat_reset / pg_switch_wal —— 写大对象、清统计、切 WAL
	for _, fn := range []string{
		"pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile",
		"lo_export", "lo_import", "lo_unlink", "lo_put", "dblink_exec",
		"pg_read_file", "pg_read_binary_file", "pg_ls_dir",
		"setval", "nextval", "pg_sleep",
		"set_config", "pg_stat_reset", "pg_stat_reset_shared", "pg_stat_reset_single_table_counters",
		"pg_switch_wal", "pg_create_restore_point",
		"pg_logical_emit_message", "pg_replication_origin_advance",
	} {
		if containsWord(qw, fn) {
			return false
		}
	}
	// `NEXT VALUE FOR <seq>`：三个词，且中间可能夹注释被压平成空白。
	// 上面那张表只能按单词判，这个词组要单独认（不是函数调用形态，没有括号）。
	if containsWordTriple(qw, "next", "value", "for") {
		return false
	}
	// EXPLAIN 要看它解释的是什么语句：
	// 带 ANALYZE / ANALYSE 时数据库会**真的执行**被解释的语句，所以
	// `EXPLAIN ANALYZE SELECT 1` 安全，`EXPLAIN ANALYZE DELETE FROM t` 不安全；
	// 不带 ANALYZE 的（含 FORMAT= / EXTENDED / PARTITIONS / VERBOSE 这些修饰语）
	// 只出计划，怎么都算只读 —— 不能因为认不出修饰语就把纯查询挡在只读模式外面。
	// 这里用 flat：可执行注释 /*!...*/ 的内容已经展开成正文。
	if strings.HasPrefix(flat, "explain") {
		rest := strings.TrimSpace(flat[len("explain"):])
		executes := false

		// 括号形式：EXPLAIN (ANALYZE, BUFFERS) ...
		if strings.HasPrefix(rest, "(") {
			i := strings.Index(rest, ")")
			if i < 0 {
				return false
			}
			opt := rest[1:i]
			if strings.TrimSpace(opt) == "" {
				return false // EXPLAIN () 是非法语句
			}
			if strings.Contains(opt, "analyse") || strings.Contains(opt, "analyze") {
				executes = true
			}
			rest = strings.TrimSpace(rest[i+1:])
		} else {
			// 无括号形式：逐个剥掉 EXPLAIN 后面的修饰语。
			//
			// 这里必须**按空白切成 token 再全等比较**，不能用「前缀匹配 + 找空格」：
			// 那样会认错词（VERBOSELY 被当 VERBOSE、FORMATTED 被当 FORMAT），
			// 剥完之后剩下的碎片就当成语句走了，判据是假的；
			// 而且分隔符可能不是空格（TAB 也是合法空白），找空格会直接判失败。
			// 每轮先剥前导注释，否则 `EXPLAIN -- c\nANALYZE DELETE` 一个修饰语都认不出。
		strip:
			for {
				rest = strings.TrimSpace(rest)
				if strings.HasPrefix(rest, "--") {
					i := strings.IndexByte(rest, '\n')
					if i < 0 {
						return false
					}
					rest = rest[i+1:]
					continue
				}
				if strings.HasPrefix(rest, "/*") {
					i := strings.Index(rest, "*/")
					if i < 0 {
						return false
					}
					rest = rest[i+2:]
					continue
				}
				if rest == "" {
					return false
				}

				// rest 来自已压平小写的 flat，不必再 ToLower ——
				// 每轮都转一次是 O(n²)：5 万个修饰语的输入会占 6 秒 CPU，
				// 而 /api/db/query 的请求体没有大小上限。
				tok := rest
				if i := strings.IndexAny(rest, " \t\r\n"); i >= 0 {
					tok = rest[:i]
				}
				switch {
				case tok == "analyze" || tok == "analyse":
					executes = true
				case tok == "extended" || tok == "partitions" || tok == "verbose":
					// 只是修饰语，继续剥
				case strings.HasPrefix(tok, "format=") && len(tok) > len("format="):
					// FORMAT=JSON / FORMAT=TREE
				default:
					break strip // 不是修饰语，剩下的就是被解释的语句
				}
				rest = rest[len(tok):]
			}
		}

		rest = strings.TrimSpace(rest)
		if rest == "" {
			return false // 只有 EXPLAIN / 修饰语，没有语句
		}
		if executes {
			// 带 ANALYZE：数据库会真的执行被解释的语句，按语句本身判
			// （方言要一路带下去，否则 MySQL 的 `EXPLAIN ANALYZE SELECT 'it\'s'`
			// 又会被保守口径判成写）
			return isReadOnlySQL(rest, kind)
		}
		// 不带 ANALYZE：理论上只出计划。但"解释的是什么"必须认得出——
		// 不能因为不认识某个修饰语就假定它不执行（那是个假判据）。
		// 认不出就返回 false，只读模式下宁可不放行。
		if !stmtRe.MatchString(rest) {
			return false
		}
		return true
	}
	// WITH 可能是纯查询（WITH x AS (SELECT ...) SELECT ...），
	// 也可能是数据修改 CTE（PG：WITH d AS (DELETE ... RETURNING *) SELECT * FROM d；
	// MySQL 8：WITH ... DELETE/UPDATE），所以要看整体有没有写操作关键字。
	//
	// 用 flat：可执行注释里的关键字也算数。
	//
	// **判词必须引号感知**（审计 第 8 条）：以前是 strings.Contains，
	// 字符串字面量里的 'delete' / 'update' 也算命中 ——
	// `WITH t AS (SELECT 'delete' AS a) SELECT * FROM t` 被判成写，
	// 只读连接上直接被拒、非只读连接上走 ExecContext，**结果集被静默丢掉**
	//（界面显示"无结果 / 影响 0 行"）。同一函数里的 into outfile / 副作用函数
	// 全都在用 quoteAwareWords，这里没有理由例外。
	if strings.HasPrefix(flat, "with") {
		withWords := strings.Join(quoteAwareWordsIn(flat, backslashEscapes), " ")
		for _, w := range []string{"insert", "update", "delete", "merge", "truncate"} {
			if containsWord(withWords, w) {
				return false
			}
		}
		return true
	}
	return readOnlyRe.MatchString(flat)
}

// Query 执行一条 SQL：查询类返回结果集，写操作返回影响行数。
func (c *Conn) Query(ctx context.Context, sqlText string, maxRows int) (*Result, error) {
	if c == nil || c.db == nil {
		return nil, fmt.Errorf("连接未建立")
	}
	sqlText = strings.TrimSpace(sqlText)
	// 去掉结尾分号：部分驱动对 "select 1;" 配 ExecContext 会报错。
	// **与 IsReadOnlySQLFor 用同一个函数**（审计 第 10 条）：两边口径不一致时，
	// `SELECT 1;;` 会被判成只读、却把 `SELECT 1;;`（两个分号）发给 MySQL 报语法错。
	sqlText = trimTrailingSemicolons(sqlText)
	if sqlText == "" {
		return nil, fmt.Errorf("SQL 是空的")
	}
	if maxRows <= 0 || maxRows > 5000 {
		maxRows = 500
	}

	res := &Result{Statement: sqlText, Columns: []string{}, Rows: [][]string{}}
	// **按连接方言判**：MySQL 的 `SELECT 'it\'s'` 是普通查询，判成写就会走
	// ExecContext 把结果集静默丢掉（界面显示"影响 0 行"）。
	res.ReadOnly = IsReadOnlySQLFor(sqlText, c.kind)
	started := time.Now()
	defer func() { res.ElapsedMs = time.Since(started).Milliseconds() }()

	if res.ReadOnly {
		rows, err := c.db.QueryContext(ctx, sqlText)
		if err != nil {
			return nil, tidyErr(err)
		}
		defer rows.Close()

		cols, err := rows.Columns()
		if err != nil {
			return nil, tidyErr(err)
		}
		res.Columns = cols

		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		for rows.Next() {
			if err := rows.Scan(ptrs...); err != nil {
				return nil, tidyErr(err)
			}
			row := make([]string, len(cols))
			for i, v := range vals {
				row[i] = formatValue(v)
			}
			res.Rows = append(res.Rows, row)
			if len(res.Rows) >= maxRows {
				res.Truncated = true
				break // 达到上限就停，剩余靠提示与缩小查询范围
			}
		}
		if err := rows.Err(); err != nil {
			return nil, tidyErr(err)
		}
		res.RowCount = len(res.Rows)
		return res, nil
	}

	r, err := c.db.ExecContext(ctx, sqlText)
	if err != nil {
		return nil, tidyErr(err)
	}
	if n, err := r.RowsAffected(); err == nil {
		res.Affected = n
	}
	return res, nil
}

// formatValue 把 driver 返回的值转成界面上能看的字符串。
func formatValue(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		if len(x) == 0 {
			return ""
		}
		if likelyBinary(x) {
			return fmt.Sprintf("<%d 字节二进制>", len(x))
		}
		return string(x)
	case time.Time:
		return x.Format("2006-01-02 15:04:05")
	default:
		return fmt.Sprint(x)
	}
}

// likelyBinary 粗略判断是不是二进制内容（前 512 字节里有 NUL 就算）。
func likelyBinary(b []byte) bool {
	limit := len(b)
	if limit > 512 {
		limit = 512
	}
	for i := 0; i < limit; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

// ---------- 元数据 ----------

// Table 是一张表/视图。
type Table struct {
	Schema  string `json:"schema"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Rows    int64  `json:"rows"`
	Comment string `json:"comment"`
}

// Column 是一个字段。
type Column struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Key      string `json:"key"`
	Default  string `json:"default"`
	Comment  string `json:"comment"`
}

// Databases 列出可访问的数据库。
func (c *Conn) Databases(ctx context.Context) ([]string, error) {
	var q string
	switch c.kind {
	case KindMySQL:
		q = `SELECT schema_name FROM information_schema.schemata
		     WHERE schema_name NOT IN ('information_schema','performance_schema','mysql','sys')
		     ORDER BY schema_name`
	default:
		q = `SELECT datname FROM pg_database
		     WHERE datistemplate = false AND datallowconn = true
		     ORDER BY datname`
	}
	rows, err := c.db.QueryContext(ctx, q)
	if err != nil {
		return nil, tidyErr(err)
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, tidyErr(err)
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// Tables 列出某个库里的表与视图。
func (c *Conn) Tables(ctx context.Context, dbName string) ([]Table, error) {
	out := []Table{}
	if c.kind == KindMySQL {
		q := `SELECT table_schema, table_name, table_type,
		             COALESCE(table_rows, 0), COALESCE(table_comment, '')
		      FROM information_schema.tables
		      WHERE table_schema = ?
		      ORDER BY table_name`
		rows, err := c.db.QueryContext(ctx, q, dbName)
		if err != nil {
			return nil, tidyErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			var t Table
			var typ string
			if err := rows.Scan(&t.Schema, &t.Name, &typ, &t.Rows, &t.Comment); err != nil {
				return nil, tidyErr(err)
			}
			t.Kind = mysqlTableKind(typ)
			out = append(out, t)
		}
		return out, rows.Err()
	}

	// PostgreSQL：按 schema 列出，默认只看用户 schema 与 public
	q := `SELECT schemaname, tablename, 'BASE TABLE' AS kind, 0 AS rows, ''
	      FROM pg_tables
	      WHERE schemaname NOT IN ('pg_catalog','information_schema')
	      UNION ALL
	      SELECT schemaname, viewname, 'VIEW', 0, ''
	      FROM pg_views
	      WHERE schemaname NOT IN ('pg_catalog','information_schema')
	      ORDER BY 1, 2`
	rows, err := c.db.QueryContext(ctx, q)
	if err != nil {
		return nil, tidyErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var t Table
		if err := rows.Scan(&t.Schema, &t.Name, &t.Kind, &t.Rows, &t.Comment); err != nil {
			return nil, tidyErr(err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func mysqlTableKind(t string) string {
	if strings.Contains(strings.ToUpper(t), "VIEW") {
		return "VIEW"
	}
	return "BASE TABLE"
}

// placeholder 返回该数据库类型的参数占位符。
//
// MySQL 用 ?，PostgreSQL（pgx）用 $1、$2…… 两者不能混用：
// 给 pgx 传 ? 会直接报 'syntax error at or near "AND"'。
func (c *Conn) placeholder(n int) string {
	if c.kind == KindPostgres {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

// Columns 列出某张表的字段。
func (c *Conn) Columns(ctx context.Context, dbName, schema, table string) ([]Column, error) {
	if c.kind == KindMySQL {
		q := `SELECT column_name, column_type, is_nullable, COALESCE(column_key, ''),
		             COALESCE(column_default, ''), COALESCE(column_comment, '')
		      FROM information_schema.columns
		      WHERE table_schema = ? AND table_name = ?
		      ORDER BY ordinal_position`
		rows, err := c.db.QueryContext(ctx, q, dbName, table)
		if err != nil {
			return nil, tidyErr(err)
		}
		defer rows.Close()
		return scanColumns(rows)
	}

	if schema == "" {
		schema = "public"
	}
	q := `SELECT column_name, COALESCE(udt_name, data_type), is_nullable,
	             '', COALESCE(column_default, ''), ''
	      FROM information_schema.columns
	      WHERE table_schema = ` + c.placeholder(1) + ` AND table_name = ` + c.placeholder(2) + `
	      ORDER BY ordinal_position`
	rows, err := c.db.QueryContext(ctx, q, schema, table)
	if err != nil {
		return nil, tidyErr(err)
	}
	defer rows.Close()
	return scanColumns(rows)
}

func scanColumns(rows *sql.Rows) ([]Column, error) {
	out := []Column{}
	for rows.Next() {
		var col Column
		var nullable string
		if err := rows.Scan(&col.Name, &col.Type, &nullable, &col.Key, &col.Default, &col.Comment); err != nil {
			return nil, tidyErr(err)
		}
		col.Nullable = strings.EqualFold(nullable, "YES")
		out = append(out, col)
	}
	return out, rows.Err()
}

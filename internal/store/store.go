// Package store 提供本地持久化（SQLite，纯 Go 驱动免 CGO）。
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"

	_ "modernc.org/sqlite"
)

// ErrNotFound 表示记录不存在。
var ErrNotFound = errors.New("记录不存在")

// Store 是数据访问入口。
type Store struct {
	db *sql.DB
	// bootAt 是**本进程启动**的时刻（Unix 毫秒），由 processBootAt() 取一次后
	// 存进来（每个 *Store 一份快照，但值相同）。MarkStaleConnections 用它区分
	// "本进程之前开始的会话"与"现在正在跑的会话" —— 见那里的说明。
	bootAt int64
}

// processBootAtValue / processBootOnce 让 bootAt 在**进程级只取一次**。
//
// 为什么必须是进程级：MarkStaleConnections 的判据是"started_at < bootAt 就当成
// 崩溃残留"。若 bootAt 每次 Open 都刷新，那么**第二个实例**打开同一份数据目录时，
// 它的 bootAt 晚于第一个实例正在跑的会话的 started_at，那条活连接就会被标成
// "程序未正常退出"（实测：st1 写入 started_at=now → 5ms 后 st2 打开 → 标记 1 条）。
// 取进程启动时刻，"本进程之前开始的"这个判据对别的实例才真的成立。
//
// 取舍写在这里：进程启动到**首次 Open** 之间开始的会话（毫秒级窗口）不会被标到，
// 会一直显示"进行中"。相比"把别人正在用的会话标脏"，这个残留是可接受的。
var (
	processBootAtValue int64
	processBootOnce    sync.Once
)

// processBootAt 返回本进程的启动时刻（Unix 毫秒），只在第一次调用时取。
func processBootAt() int64 {
	processBootOnce.Do(func() { processBootAtValue = time.Now().UnixMilli() })
	return processBootAtValue
}

const schema = `
CREATE TABLE IF NOT EXISTS targets(
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  host         TEXT NOT NULL,
  port         INTEGER NOT NULL DEFAULT 22,
  username     TEXT NOT NULL,
  auth_kind    TEXT NOT NULL DEFAULT 'password',
  secret_id    TEXT NOT NULL DEFAULT '',
  tags         TEXT NOT NULL DEFAULT '[]',
  grp          TEXT NOT NULL DEFAULT '',
  start_dir    TEXT NOT NULL DEFAULT '',
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS secrets(
  id         TEXT PRIMARY KEY,
  nonce      BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS connections(
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id  TEXT NOT NULL DEFAULT '',
  name       TEXT NOT NULL DEFAULT '',
  host       TEXT NOT NULL,
  port       INTEGER NOT NULL,
  username   TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  ended_at   INTEGER NOT NULL DEFAULT 0,
  exit_code  INTEGER NOT NULL DEFAULT 0,
  bytes_in   INTEGER NOT NULL DEFAULT 0,
  bytes_out  INTEGER NOT NULL DEFAULT 0,
  error      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_connections_started ON connections(started_at DESC);
CREATE TABLE IF NOT EXISTS settings(
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS compliance_reports (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  target_id  TEXT NOT NULL DEFAULT '',
  target     TEXT NOT NULL DEFAULT '',
  score      INTEGER NOT NULL DEFAULT 0,
  total      INTEGER NOT NULL DEFAULT 0,
  pass       INTEGER NOT NULL DEFAULT 0,
  fail       INTEGER NOT NULL DEFAULT 0,
  manual     INTEGER NOT NULL DEFAULT 0,
  err_count  INTEGER NOT NULL DEFAULT 0,
  elapsed_ms INTEGER NOT NULL DEFAULT 0,
  results    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_compliance_ts ON compliance_reports(ts);
CREATE INDEX IF NOT EXISTS idx_compliance_target ON compliance_reports(target_id);
-- 下面三张表以前是"首次调用时建"（挂在包级 sync.Once 上），
-- 而 sync.Once 是**进程级**、不是"每个数据库一次"：同进程出现第二个 *Store 时
-- 那三张表就是没有（实测库B 全报 no such table）；更糟的是包级错误变量只试一次，
-- 首次失败（瞬时 locked、磁盘满）之后本进程永远返回旧错误、表再也不建。
-- 放进 schema（每次 Open 都跑、CREATE IF NOT EXISTS 幂等）才是对的。
CREATE TABLE IF NOT EXISTS db_conns (
  id         TEXT PRIMARY KEY,
  target_id  TEXT NOT NULL DEFAULT '',
  target     TEXT NOT NULL DEFAULT '',
  name       TEXT NOT NULL DEFAULT '',
  kind       TEXT NOT NULL DEFAULT '',
  addr       TEXT NOT NULL DEFAULT '',
  username   TEXT NOT NULL DEFAULT '',
  database   TEXT NOT NULL DEFAULT '',
  secret_id  TEXT NOT NULL DEFAULT '',
  read_only  INTEGER NOT NULL DEFAULT 1,
  max_rows   INTEGER NOT NULL DEFAULT 500,
  created_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_db_conns_target ON db_conns(target_id);
CREATE TABLE IF NOT EXISTS known_hosts (
  host        TEXT NOT NULL,
  port        INTEGER NOT NULL,
  key_type    TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL DEFAULT '',
  first_seen  INTEGER NOT NULL DEFAULT 0,
  last_seen   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (host, port)
);
CREATE TABLE IF NOT EXISTS scan_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  target_id TEXT NOT NULL DEFAULT '',
  target_name TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL DEFAULT '',
  rule_id TEXT NOT NULL DEFAULT '',
  rule_name TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT '',
  source_ip TEXT NOT NULL DEFAULT '',
  line_no INTEGER NOT NULL DEFAULT 0,
  decoded INTEGER NOT NULL DEFAULT 0,
  sample TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scan_events_ts ON scan_events(ts);
CREATE INDEX IF NOT EXISTS idx_scan_events_ip ON scan_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_scan_events_target ON scan_events(target_id);
`

// Open 打开（或创建）数据库。若发现数据库损坏会自动留档并重建，
// 补救说明被丢弃 —— 需要提示用户的调用方请用 OpenDetail。
func Open(path string) (*Store, error) {
	s, _, err := OpenDetail(path)
	return s, err
}

// OpenDetail 打开数据库，并在打不开时做**有损但可追溯**的补救。
//
// 为什么要有它：数据库文件损坏（磁盘满、断电、被别的程序写坏、手工改过）
// 时 sqlite 会拒绝打开，旧实现直接返回错误 → 程序弹个框就退出，用户没有任何
// 出路，只能自己去数据目录删文件 —— 而对安全运维来说那可能是**证据**。
//
// 补救三步，侵入性从小到大，**永不删除任何文件**：
//
//  1. 把 `-wal` / `-shm` 移到一边再打开。SQLite 最常见的"打不开"其实是这两个
//     副文件与主库不一致，移走后未提交的事务会丢，主库数据完整。
//  2. 真打不开就当成损坏：把 `.db`（连同副文件）**改名**为
//     `<name>.corrupt-<时间戳>` 留档，再建一个空库让程序能起来。
//  3. 改名都失败（权限/占用）就如实报错，把原始错误一并带上。
//
// 返回的 note 是给人看的补救说明（空串表示一切正常），调用方应当提示用户。
func OpenDetail(path string) (*Store, string, error) {
	s, err := openOnce(path)
	if err == nil {
		return s, "", nil
	}
	if !looksCorrupt(err) {
		return nil, "", err
	}
	original := err

	// stamp 只取一次，第一步与第三步共用 —— 各取一次的话两个名字可能差一秒，
	// 那句 note 让用户按 `.corrupt-*` 去找，找到的会是几乎空的主库文件，
	// 而真正的数据在另一个名字（`.stale-*`）里。
	// 带上纳秒：Windows 上 os.Rename 是 MoveFileEx(REPLACE_EXISTING)，
	// 同一秒内的第二次留档会把第一次覆盖掉。
	stamp := time.Now().Format("20060102-150405.000000000")

	// 第一步：副文件不一致。
	//
	// **措辞要准确**：实测提交过数据之后，只看主库文件连 `targets` 表都不存在
	// （-wal 有 90KB）—— 副文件里放的是**已提交**的数据。移走它等于把最新数据
	// 挪到一边，绝不能写成"只是丢了未提交的事务、主库数据完整"。
	//
	// 移走的路径**必须留在作用域里**：以前它是 `if` 语句内的局部变量，第二步
	// 仍打不开时错误里就一个字都不提副文件落点 —— 用户按提示处置会漏掉那个
	// 可能含着全部已提交数据的文件。
	//
	// 打开之前先记下"旁边有哪些副文件"：事后（打开失败时）再 Stat 就分不清
	// "本来没有"与"被驱动删了"。见 missingSidecars。
	existedSidecars := sidecarExisted(path)

	movedSidecars, moveErr := moveSidecars(path, stamp)
	if moveErr == nil && len(movedSidecars) > 0 {
		if s2, err2 := openOnce(path); err2 == nil {
			return s2, "数据库的 WAL/SHM 副文件与主库不一致，已把副文件移到" +
				movedSidecarText(movedSidecars, " ") +
				"请**保留**这些文件：它们里面可能含着全部已提交的数据" +
				"（不只是未提交的事务），主库文件本身可能是旧的。", nil
		} else {
			// 第二次打开**又被驱动删掉了副文件**。实测：主库不是数据库、
			// 旁边挂着 -shm 时，openOnce 返回的 error 是
			// `PRAGMA journal_mode=WAL 失败: file is not a database (26)`——
			// 看着像"损坏"，而 sqlite 是在**删除 -shm/-wal 的过程中**失败的，
			// 文件已经不在了。所以下面必须重新 Stat 一遍，不能拿"移走了什么"
			// 当作"原错发生时还剩下什么"。
			if lost := missingSidecars(path, existedSidecars, movedSidecars); len(lost) > 0 {
				original = fmt.Errorf("%w（重试打开时驱动已删除 %s：请保留 %s，"+
					"主库里可能是旧数据、真正的最新数据在副文件里）",
					original, strings.Join(lost, "、"),
					orNoneText(movedDestinations(movedSidecars), "数据库目录里的留档文件"))
			}
		}
	}

	// 第二步：确认确实损坏（而不是"只是需要重建索引"之类）
	if !integrityBroken(path) {
		// 走到这里说明"打不开，但不像数据库损坏"（例如文件被占用）。
		// 副文件落点必须带出去：可能已经有副文件被移走、甚至有副文件被驱动删掉，
		// 用户手里的原始错误本身不会提这两件事。
		if len(movedSidecars) > 0 {
			return nil, "", fmt.Errorf("%w；副文件已移到%s请保留（它可能含着全部已提交的数据）",
				original, movedSidecarText(movedSidecars, " "))
		}
		return nil, "", original
	}

	// 第三步：留档 + 新建。只改名，绝不删除。
	backup := path + ".corrupt-" + stamp
	if renameErr := os.Rename(path, backup); renameErr != nil {
		return nil, "", fmt.Errorf("数据库已损坏，且留档失败（%v）；原文件 %s 请手动处理%s。原始错误：%w",
			renameErr, path,
			movedSidecarText(movedSidecars, "；副文件已移到 "), original)
	}
	// 副文件的 rename **不能再吞掉失败**：-wal 里可能就是全部已提交的数据，
	// 改名不成（被占用/权限）时用户得知道它还挂在原路径上、别当垃圾删了。
	var sidecarErrs []string
	for _, ext := range []string{"-wal", "-shm"} {
		src := path + ext
		if _, statErr := os.Stat(src); statErr != nil {
			continue // 本来就没有，不算失败
		}
		if renameErr := os.Rename(src, backup+ext); renameErr != nil {
			sidecarErrs = append(sidecarErrs, fmt.Sprintf("%s（%v）", src, renameErr))
		}
	}
	s3, err3 := openOnce(path)
	if err3 != nil {
		return nil, "", fmt.Errorf("数据库已损坏，留档为 %s 后新建也失败: %w", backup, err3)
	}
	return s3, "数据库已损坏（未通过完整性检查），原文件已留档为 " + backup +
		"，现在使用的是新建的空库。旧数据的恢复请从留档文件入手，不要删除它。" +
		movedSidecarText(movedSidecars, "另有副文件也已移到 ") +
		sidecarFailText(sidecarErrs), nil
}

// movedSidecarText 把"已移走的副文件"拼进 note / 错误文本。
//
// 存在的理由：第一步移走副文件是**有损**动作（实测 -wal 里放的是**已提交**的
// 数据），只要后续仍然失败，交出去的文本里就必须带出这个落点 —— 否则用户按
// 提示去处理那个 `.db` 文件时，不会想到旁边还躺着一个更值钱的 `.stale-*`。
//
// 只拼文本、不接触 %w：错误链要由调用方自己的 fmt.Errorf 接上。
func movedSidecarText(moved []movedSidecar, prefix string) string {
	if len(moved) == 0 {
		return ""
	}
	dsts := make([]string, 0, len(moved))
	for _, m := range moved {
		dsts = append(dsts, m.Dst)
	}
	return prefix + strings.Join(dsts, "、") + "。"
}

// sidecarFailText 把副文件改名失败的清单拼成一句人话（空列表返回空串）。
func sidecarFailText(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	return " 注意：以下副文件没能移到留档路径，可能还带着数据，请手动保留：" +
		strings.Join(errs, "、") + "。"
}

// orNoneText 列表为空时给一句兜底说法（别在给用户的文本里出现空列表）。
func orNoneText(items []string, fallback string) string {
	if len(items) == 0 {
		return fallback
	}
	return strings.Join(items, "、")
}

// movedDestinations 只取留档路径（给用户看的那些）。
func movedDestinations(moved []movedSidecar) []string {
	out := make([]string, 0, len(moved))
	for _, m := range moved {
		out = append(out, m.Dst)
	}
	return out
}

// movedSidecar 是一份被移到一边的副文件：Src 是原路径，Dst 是留档路径。
//
// 两个都要：给用户的文本要报 Dst（他去哪里找），而 missingSidecars 判断
// "驱动删了没"要拿 Src 与移走清单对照 —— 只有 Dst 的话，字符串对不上，
// 我们亲手移走的文件会被误报成"驱动删掉了"。
type movedSidecar struct {
	Src string
	Dst string
}

// sidecarExisted 记录 `path` 旁边当前存在哪些副文件后缀（用于事后判断"被删了"）。
func sidecarExisted(path string) []string {
	var out []string
	for _, ext := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(path + ext); err == nil {
			out = append(out, ext)
		}
	}
	return out
}

// missingSidecars 从"打开之前存在过"的清单里挑出**现在真的没了**的那些，
// 拼成可直接写进错误文本的路径列表。
//
// 为什么要单独查一遍：sqlite 驱动在 openOnce 失败时可能已经把副文件删掉
// （实测：主库不是数据库 + 有 -wal 时，报 `file is not a database (26)` 的同时
// 副文件消失）。这属于**数据丢失**，必须写进交出去的文本里 —— 用户手里只有
// 一句"file is not a database"，他不会知道旁边那个装着最新数据的 -wal/-shm
// 已经没了，也就不会去备份里找。
func missingSidecars(path string, existed []string, moved []movedSidecar) []string {
	movedSrc := map[string]bool{}
	for _, m := range moved {
		movedSrc[m.Src] = true
	}
	var lost []string
	for _, ext := range existed {
		p := path + ext
		if movedSrc[p] {
			continue // 是我们自己移走的，不是被删的
		}
		if _, err := os.Stat(p); err != nil {
			lost = append(lost, p)
		}
	}
	return lost
}

// looksCorrupt 判断错误是否属于"文件不是合法数据库/已损坏"这一类。
//
// 只认这一类：权限不足、被别的进程占用、路径不存在这些**不该**触发留档重建
// （那会把用户还能救的数据改名，白白吓一跳）。
func looksCorrupt(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"file is not a database",
		"file is encrypted or is not a database",
		"database disk image is malformed",
		"sqlite_corrupt",
		"malformed database schema",
		"database corruption",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// moveSidecars 把 -wal / -shm 移到一边（只移动，不删除），返回**已经移走的全部**。
// 返回的是 Src/Dst 成对的清单而不是只返回第一个目标：调用方要拿 Dst 写进
// note/错误（漏掉任何一个都意味着用户手里那份"可能含着已提交数据"的文件没有
// 被点名），也要拿 Src 判断"后来没了的那份到底是被驱动删了、还是我们自己移的"。
// 改名失败时也把此前已移走的那些一并返回 —— 失败点之前的副文件已经在那边了。
// stamp 由调用方传入并复用，保证与第三步的留档名是同一时刻。
func moveSidecars(path, stamp string) ([]movedSidecar, error) {
	var moved []movedSidecar
	for _, ext := range []string{"-wal", "-shm"} {
		src := path + ext
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := src + ".stale-" + stamp
		if err := os.Rename(src, dst); err != nil {
			return moved, err
		}
		moved = append(moved, movedSidecar{Src: src, Dst: dst})
	}
	return moved, nil
}

// integrityBroken 跑一次 SQLite 的完整性检查；返回 true 表示**确实损坏**。
//
// 必须把两种情况分开：① 检查结果不是 "ok"（真损坏）；② 检查本身跑不起来
// （文件根本不是数据库、或被人占用/锁住）。②**不能**算损坏 —— 那会触发
// 改名重建，把用户还能救的数据挪走，纯粹是虚惊一场。
//
// 连接要带 busy_timeout：不加的话被别的进程持锁时会立刻失败，直接被判成损坏。
func integrityBroken(path string) bool {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return true // 驱动都开不了：文件多半不是数据库
	}
	defer db.Close()
	// PRAGMA 发不出去 = 查不动，不是"损坏"
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		return false
	}
	// 先用一个轻量查询确认它真能当 SQLite 用
	var one int
	if err := db.QueryRow("SELECT 1").Scan(&one); err != nil {
		return looksCorrupt(err) // "file is not a database" 之类才算
	}
	var res string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&res); err != nil {
		return looksCorrupt(err)
	}
	return !strings.EqualFold(strings.TrimSpace(res), "ok")
}

// openOnce 是一次纯粹的打开尝试（不做任何补救）。
func openOnce(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("打开数据库失败: %w", err)
	}
	// 桌面场景单连接足够，且能避免 SQLITE_BUSY。
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("执行 %s 失败: %w", pragma, err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化表结构失败: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	// 取**进程启动**的时刻（不是本次打开的时刻）：MarkStaleConnections 只标
	// bootAt 之前的记录，取进程级才是"另一次运行留下的"这个语义 —— 每次 Open
	// 都刷新的话，同机第二个实例会把前一个实例正在跑的会话标脏。窗口代价见
	// processBootAt 的说明。
	return &Store{db: db, bootAt: processBootAt()}, nil
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().UnixMilli() }

// ---------- 目标 ----------

// ListTargets 返回全部目标（按名称排序）。
func (s *Store) ListTargets() ([]domain.Target, error) {
	rows, err := s.db.Query(`SELECT id,name,host,port,username,auth_kind,secret_id,tags,grp,start_dir,
		created_at,updated_at,last_used_at FROM targets ORDER BY grp ASC, name ASC`)
	if err != nil {
		return nil, fmt.Errorf("查询目标失败: %w", err)
	}
	defer rows.Close()
	return scanTargets(rows)
}

// RecentTargets 返回最近使用过的目标。
func (s *Store) RecentTargets(limit int) ([]domain.Target, error) {
	rows, err := s.db.Query(`SELECT id,name,host,port,username,auth_kind,secret_id,tags,grp,start_dir,
		created_at,updated_at,last_used_at FROM targets
		WHERE last_used_at > 0 ORDER BY last_used_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询最近目标失败: %w", err)
	}
	defer rows.Close()
	return scanTargets(rows)
}

func scanTargets(rows *sql.Rows) ([]domain.Target, error) {
	out := []domain.Target{}
	for rows.Next() {
		var t domain.Target
		var tags string
		if err := rows.Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.Username, &t.AuthKind,
			&t.SecretID, &tags, &t.Group, &t.StartDir, &t.CreatedAt, &t.UpdatedAt, &t.LastUsedAt); err != nil {
			return nil, fmt.Errorf("读取目标失败: %w", err)
		}
		_ = json.Unmarshal([]byte(tags), &t.Tags)
		if t.Tags == nil {
			t.Tags = []string{}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetTarget 取单个目标。
func (s *Store) GetTarget(id string) (domain.Target, error) {
	var t domain.Target
	var tags string
	err := s.db.QueryRow(`SELECT id,name,host,port,username,auth_kind,secret_id,tags,grp,start_dir,
		created_at,updated_at,last_used_at FROM targets WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &t.Host, &t.Port, &t.Username, &t.AuthKind,
			&t.SecretID, &tags, &t.Group, &t.StartDir, &t.CreatedAt, &t.UpdatedAt, &t.LastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	if err != nil {
		return t, fmt.Errorf("读取目标失败: %w", err)
	}
	_ = json.Unmarshal([]byte(tags), &t.Tags)
	if t.Tags == nil {
		t.Tags = []string{}
	}
	return t, nil
}

// SaveTarget 新建或更新目标。
func (s *Store) SaveTarget(t domain.Target) (domain.Target, error) {
	ts := now()
	tags, _ := json.Marshal(t.Tags)
	if t.Tags == nil {
		tags = []byte("[]")
	}
	if t.CreatedAt == 0 {
		t.CreatedAt = ts
	}
	t.UpdatedAt = ts
	_, err := s.db.Exec(`INSERT INTO targets(id,name,host,port,username,auth_kind,secret_id,tags,grp,start_dir,
		created_at,updated_at,last_used_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, host=excluded.host, port=excluded.port, username=excluded.username,
			auth_kind=excluded.auth_kind, secret_id=excluded.secret_id, tags=excluded.tags,
			grp=excluded.grp, start_dir=excluded.start_dir, updated_at=excluded.updated_at`,
		t.ID, t.Name, t.Host, t.Port, t.Username, t.AuthKind, t.SecretID, string(tags), t.Group, t.StartDir,
		t.CreatedAt, t.UpdatedAt, t.LastUsedAt)
	if err != nil {
		return t, fmt.Errorf("保存目标失败: %w", err)
	}
	return t, nil
}

// DeleteTarget 删除目标及其凭据。
//
// 两条 DELETE 必须在**一个事务**里：以前先删 targets 再删 secrets，第二次删除
// 的错误被 `_` 吞掉，于是失败时留下一份**孤儿密文**（目标没了、密文永远没人删，
// 而它是能解出明文口令的）。现在任一步失败整体回滚并把错误交出去。
func (s *Store) DeleteTarget(id string) error {
	t, err := s.GetTarget(id)
	if err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("删除目标失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 成功后 Rollback 返回 ErrTxDone，无害

	if _, err := tx.Exec(`DELETE FROM targets WHERE id = ?`, id); err != nil {
		return fmt.Errorf("删除目标失败: %w", err)
	}
	if t.SecretID != "" {
		if _, err := tx.Exec(`DELETE FROM secrets WHERE id = ?`, t.SecretID); err != nil {
			return fmt.Errorf("删除目标凭据失败: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("删除目标失败: %w", err)
	}
	return nil
}

// TouchTarget 更新最后使用时间。
func (s *Store) TouchTarget(id string) error {
	_, err := s.db.Exec(`UPDATE targets SET last_used_at = ? WHERE id = ?`, now(), id)
	if err != nil {
		return fmt.Errorf("更新使用时间失败: %w", err)
	}
	return nil
}

// ---------- 凭据密文 ----------

// PutSecret 写入（或覆盖）一条密文。
func (s *Store) PutSecret(id string, nonce, ciphertext []byte) error {
	_, err := s.db.Exec(`INSERT INTO secrets(id,nonce,ciphertext,created_at) VALUES(?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET nonce=excluded.nonce, ciphertext=excluded.ciphertext`,
		id, nonce, ciphertext, now())
	if err != nil {
		return fmt.Errorf("保存凭据失败: %w", err)
	}
	return nil
}

// GetSecret 读取一条密文。
func (s *Store) GetSecret(id string) (nonce, ciphertext []byte, err error) {
	err = s.db.QueryRow(`SELECT nonce,ciphertext FROM secrets WHERE id = ?`, id).Scan(&nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("读取凭据失败: %w", err)
	}
	return nonce, ciphertext, nil
}

// ---------- 连接历史 ----------

// AddConnection 记录一次连接开始。
func (s *Store) AddConnection(rec domain.ConnectionRecord) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO connections(target_id,name,host,port,username,started_at)
		VALUES(?,?,?,?,?,?)`, rec.TargetID, rec.Name, rec.Host, rec.Port, rec.Username, rec.StartedAt)
	if err != nil {
		return 0, fmt.Errorf("写入连接历史失败: %w", err)
	}
	return res.LastInsertId()
}

// FinishConnection 更新一次连接的结束状态。
func (s *Store) FinishConnection(id int64, exitCode int, bytesIn, bytesOut int64, errMsg string) error {
	_, err := s.db.Exec(`UPDATE connections SET ended_at=?, exit_code=?, bytes_in=?, bytes_out=?, error=?
		WHERE id = ?`, now(), exitCode, bytesIn, bytesOut, errMsg, id)
	if err != nil {
		return fmt.Errorf("更新连接历史失败: %w", err)
	}
	return nil
}

// DeleteConnection 删掉一条连接历史。
func (s *Store) DeleteConnection(id int64) error {
	_, err := s.db.Exec(`DELETE FROM connections WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("删除连接历史失败: %w", err)
	}
	return nil
}

// ClearConnections 清空连接历史；targetID 为空表示全部。
// 返回删掉的条数。
func (s *Store) ClearConnections(targetID string) (int64, error) {
	var res sql.Result
	var err error
	if targetID == "" {
		res, err = s.db.Exec(`DELETE FROM connections`)
	} else {
		res, err = s.db.Exec(`DELETE FROM connections WHERE target_id = ?`, targetID)
	}
	if err != nil {
		return 0, fmt.Errorf("清空连接历史失败: %w", err)
	}
	return res.RowsAffected()
}

// ListConnections 返回连接历史。
func (s *Store) ListConnections(limit int) ([]domain.ConnectionRecord, error) {
	rows, err := s.db.Query(`SELECT id,target_id,name,host,port,username,started_at,ended_at,
		exit_code,bytes_in,bytes_out,error FROM connections ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("查询连接历史失败: %w", err)
	}
	defer rows.Close()
	out := []domain.ConnectionRecord{}
	for rows.Next() {
		var c domain.ConnectionRecord
		if err := rows.Scan(&c.ID, &c.TargetID, &c.Name, &c.Host, &c.Port, &c.Username,
			&c.StartedAt, &c.EndedAt, &c.ExitCode, &c.BytesIn, &c.BytesOut, &c.Error); err != nil {
			return nil, fmt.Errorf("读取连接历史失败: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---------- 设置 ----------

// GetSetting 读取一个设置项。
func (s *Store) GetSetting(key, def string) string {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v); err != nil {
		return def
	}
	return v
}

// PutSetting 写入一个设置项。
func (s *Store) PutSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	if err != nil {
		return fmt.Errorf("保存设置失败: %w", err)
	}
	return nil
}

// PruneConnections 清理连接历史：删掉超过 keepDays 天的记录，并且只保留最近 keepMax 条。
// 两个条件任一为 0 表示该条件不启用。返回删除的行数。
func (s *Store) PruneConnections(keepDays, keepMax int) (int64, error) {
	var removed int64
	if keepDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -keepDays).UnixMilli()
		res, err := s.db.Exec(`DELETE FROM connections WHERE started_at < ?`, cutoff)
		if err != nil {
			return removed, fmt.Errorf("清理过期连接历史失败: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	if keepMax > 0 {
		res, err := s.db.Exec(`DELETE FROM connections WHERE id NOT IN (
			SELECT id FROM connections ORDER BY started_at DESC LIMIT ?)`, keepMax)
		if err != nil {
			return removed, fmt.Errorf("清理超额连接历史失败: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	return removed, nil
}

// MarkStaleConnections 把"没有结束时间"的连接记录标记为中断。
// 程序被强杀、崩溃或断电时会留下这种记录（ended_at = 0），启动时清理一次，避免历史里永远挂着"进行中"。
//
// **只标"本进程启动之前就开始了"的记录**（started_at < bootAt）。以前是无条件
// 把全表 ended_at=0 都标掉，于是两个实例共用一份数据目录时，后启动的那个会把
// 前一个实例**正在跑**的会话标成"程序未正常退出"，历史里出现假的中断记录。
//
// bootAt 必须是**进程级**（见 processBootAt）：如果它每次 Open 都刷新，判据就退化成
// "本次打开之前"，第二个实例的 bootAt 恰好晚于第一个实例刚建的会话 → 照样标脏
// （实测复现过：同进程两次 Open 同一个库，活连接被标了 1 条）。
//
// 窗口的代价写在明处：本进程启动、但在首次打开数据库之前开始的会话不会被标到
// （毫秒级窗口）。真被强杀在同一毫秒里，这条记录会一直显示"进行中" ——
// 相比"把别人正在用的会话标脏"，这个残留是可接受的。
func (s *Store) MarkStaleConnections(reason string) (int64, error) {
	res, err := s.db.Exec(`UPDATE connections SET ended_at = started_at, exit_code = 1, error = ?
		WHERE ended_at = 0 AND started_at < ?`, reason, s.bootAt)
	if err != nil {
		return 0, fmt.Errorf("标记中断的连接记录失败: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// migrate 为老库补新增列（SQLite 不支持 ADD COLUMN IF NOT EXISTS，先查 PRAGMA）。
func migrate(db *sql.DB) error {
	have := map[string]bool{}
	rows, err := db.Query(`PRAGMA table_info(targets)`)
	if err != nil {
		return fmt.Errorf("读取表结构失败: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return fmt.Errorf("解析表结构失败: %w", err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !have["start_dir"] {
		if _, err := db.Exec(`ALTER TABLE targets ADD COLUMN start_dir TEXT NOT NULL DEFAULT ''`); err != nil {
			// 先 PRAGMA 查、再 ALTER，中间没有锁：两个实例同时打开一个老库时，
			// 两边都可能读到"还没有 start_dir"，慢的那个就撞上
			// `duplicate column name: start_dir`。这是"别人已经迁移好了"，
			// 不是失败 —— 当成已迁移忽略，否则第二个实例直接起不来。
			if !isDuplicateColumn(err) {
				return fmt.Errorf("迁移 start_dir 列失败: %w", err)
			}
		}
	}

	// 核查报告的秒级时间戳迁移。
	//
	// 放在这里而不是 ensureComplianceReports：那个函数原来带包级 sync.Once，
	// scope 是"进程"而不是"这个库"——同一进程里第二次打开别的库就不会再迁移
	// （-web 与桌面模式并存、或将来任何两个 Store 指向同一个 .db 都会踩到）。
	// 建表已经在 schema 里（每次 Open 都跑），所以这里可以直接 UPDATE。
	if _, err := db.Exec(complianceTSMigration); err != nil {
		return fmt.Errorf("迁移核查报告时间戳失败: %w", err)
	}

	// 主机密钥的秒级时间戳迁移（同 complianceTSMigration 的理由：老库的秒值
	// 不加迁移会按毫秒解释成 1970-01-21）。known_hosts 已经建在 schema 里。
	if _, err := db.Exec(hostKeyTSMigration); err != nil {
		return fmt.Errorf("迁移主机密钥时间戳失败: %w", err)
	}
	return nil
}

// isDuplicateColumn 判断错误是不是"这一列已经有了"。
//
// SQLite 的措辞是 `duplicate column name: start_dir`（modernc 驱动原样透出），
// 所以按小写子串匹配，不锁死具体列名 —— 将来再加列也能复用。
func isDuplicateColumn(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "duplicate column name")
}

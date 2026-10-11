// Package store 提供本地持久化（SQLite，纯 Go 驱动免 CGO）。
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/awdshell/internal/domain"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrNotFound 表示记录不存在。
var ErrNotFound = errors.New("记录不存在")

// Store 是数据访问入口。
type Store struct {
	db *sql.DB
	// dbPath 是本 Store 打开的那个 .db 文件路径。留着它是为了让"另一条连接"
	// 能指向同一个库（诊断、测试注入并发写），而不必把路径在调用链上传来传去。
	dbPath string
	// bootAt 是**本进程启动**的时刻（Unix 毫秒），由 processBootAt() 取一次后
	// 存进来（每个 *Store 一份快照，但值相同）。它是"崩溃残留"判据的退回方案：
	// 只有在本进程启动之前就开始了、且晚于 last_clean_exit 的记录才算是
	// 上一次运行留下的 —— 见 MarkStaleConnections。
	bootAt int64
}

// schemaVersion 是当前程序认识的库结构版本（写在 PRAGMA user_version 里）。
//
// 为什么要它：迁移逻辑是"补列 + 区间 UPDATE"，它是幂等的，但**不能回答
// "这个库比我新还是比我旧"**。用旧版本打开一个被新版迁移过的库时，老程序会
// 照常打开、照常写，然后按自己的理解解释新数据 —— 全程没有任何提示。
// 打开时比一下版本，比自己新就明确拒绝，把"老客户端写坏新库"这条路堵掉。
//
// 1 = 本文件最早的形态（targets 补 start_dir、秒值迁移）；
// 2 = connections.owner_pid 列（会话归属，用于区分"崩溃残留"与"别人在跑"）。
const schemaVersion = 2

// processBootAtValue / processBootOnce 让 bootAt 在**进程级只取一次**。
//
// 为什么必须是进程级：MarkStaleConnections 的判据里有"本进程启动之前开始的
// 才算残留"这一条。若 bootAt 每次 Open 都刷新，那么**第二个实例**打开同一份
// 数据目录时，它的 bootAt 晚于第一个实例正在跑的会话的 started_at，那条活连接
// 就会被标成"程序未正常退出"（实测：st1 写入 started_at=now → 5ms 后 st2 打开
// → 标记 1 条）。取进程启动时刻，"本进程之前开始的"这个判据才真的成立。
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
  error      TEXT NOT NULL DEFAULT '',
  -- owner_pid：写下这条"进行中"记录的程序进程号（老库补列见 migrate）。
  -- 它是 MarkStaleConnections 的判据：跨进程时"哪个进程还活着"才是真判据，
  -- bootAt 只是进程自己的启动时刻，管不了别的实例。
  owner_pid  INTEGER NOT NULL DEFAULT 0
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
	// **快照必须在第一次 openOnce 之前**：sqlite 会在打开过程中把副文件
	// （-wal/-shm）删掉，事后 Stat 已经分不清"本来就没有"与"被驱动丢了"。
	// 以前这份快照取在第一次 openOnce 之后，于是"驱动把 -wal 丢了"这句话
	// 几乎永远不会触发 —— 实测"主库 4096 字节、全部已提交数据在 12392 字节的
	// -wal 里、把 -wal 覆盖成垃圾"时 OpenDetail 返回 ok + note=""，用户拿到一个
	// 空库、还继续往同一个文件写 schema。见 missingSidecarPaths。
	existedSidecars := sidecarSnapshot(path)

	s, err := openOnce(path)
	if err == nil {
		// openOnceSucceededHook 是测试注入点（生产路径恒为 nil）：在"打开成功、
		// 检测之前"这个位置触发一次。存在的理由见变量说明。
		if openOnceSucceededHook != nil {
			openOnceSucceededHook(s)
		}
		// 成功路径也必须查一遍：驱动"静默丢弃坏掉的 -wal 然后打开成功"正是
		// 最需要提示的那种形态 —— 没有 error、没有 note，用户以为一切正常。
		//
		// 上面的快照**必须取在第一次 openOnce 之前**（见函数开头）：取在之后的话，
		// 被驱动删掉的副文件在快照里就已经不存在了，这个分支永远不会触发
		// （这正是审计 H1 的根因）。
		if lost := discardedDataSidecarPaths(path, existedSidecars, nil); len(lost) > 0 {
			return s, "警告：打开之前这些副文件就在数据库旁边，打开之后被数据库驱动丢弃了：" +
				strings.Join(lost, "、") + "。丢弃可能发生在驱动判定它无法恢复时，" +
				"里面**可能含着全部已提交的数据**（不只是未提交的事务）；主库本身可能是旧的。" +
				"请立即停止写入（每次写入都在覆盖仅存的旧数据），先把这个库文件另存一份，" +
				"再从备份里找回副文件重试。", nil
		}
		// 上一次这个库损坏过、已经被留档成 `.corrupt-*`，而当前路径上正好是一个
		// **空库**时，必须把留档落点再说一次：那次补救的 note 只在当时的会话里
		// 出现过（弹框 + 日志），下次启动 openOnce 成功、note 为空串，用户看到的
		// 是"一切正常"，没有任何线索指向旁边那份旧数据 —— 这正是"拿到空库且无线索"
		// 的形态（复审 P2-4：只钉了错误文本，真实形态没人守）。
		// 只在库**确实空着**时说：用户重新用起来之后不该每次启动都被念一遍
		//（设计上还要求他保留那份留档文件，所以文件会一直躺在那里）。
		if archived := archivedLibraryNote(s, path); archived != "" {
			return s, archived, nil
		}
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
	movedSidecars, moveErr := moveSidecars(path, stamp)

	// 重试打开。**必须查一遍"驱动是不是又删了副文件"**：实测主库不是数据库、
	// 旁边挂着 -shm 时，openOnce 返回 `file is not a database (26)`——看着像
	// "损坏"，而 sqlite 是在**删除 -shm/-wal 的过程中**失败的，文件已经没了。
	// 所以只能拿"打开前存在、又不是我们移走的"来判，不能拿"移走了什么"当证据。
	//
	// 这段以前嵌在 `len(moved)>0` 分支里：一个副文件都没移成时（例如改名被
	// 占用挡住）删除检测根本不跑，用户手里那句 "file is not a database" 不会
	// 告诉他旁边那个装着全部已提交数据的 -wal 已经没了。
	if moveErr == nil && len(movedSidecars) > 0 {
		if s2, err2 := openOnce(path); err2 == nil {
			return s2, "数据库的 WAL/SHM 副文件与主库不一致，已把副文件移到" +
				movedSidecarText(movedSidecars, " ") +
				"请**保留**这些文件：它们里面可能含着全部已提交的数据" +
				"（不只是未提交的事务），主库文件本身可能是旧的。", nil
		}
	}
	lostSidecars := missingSidecarPaths(path, existedSidecars, movedSidecars)
	original = wrapLostSidecars(original, lostSidecars, movedSidecars, moveErr)

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
	backup := path + corruptArchiveSuffix + stamp
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
	// **必须在 openOnce(path) 之前再算一次"驱动删了哪些副文件"**：
	//
	//   - 上面那次（第一步之后）算出来的那份只喂给了 error 链（wrapLostSidecars），
	//     而第三步是**成功返回**、拼的是下面这条全新 note —— original 根本不参与，
	//     于是"副文件被驱动删掉"这条信息在成功路径上被整条丢掉（实测：主库 21 字节
	//     垃圾 + 旁边一份 39 字节非空 -wal，openOnce 建连接时就把 -wal 删了 →
	//     moveSidecars 无事可做 → missingSidecarPaths 正确报出它 → 用户拿到的 note
	//     里一个字都没提 -wal）。这恰恰是最该说明的场景：那份 -wal 里可能装着
	//     **全部已提交的数据**，用户不知道它已经没了就不会去备份里找，
	//     还会继续往新建的空库上写。
	//
	//   - **不能挪到 openOnce(path) 之后**：新建的库同样是 WAL 模式，
	//     这一次打开会在同一个路径上**重新建出**一个空的 -wal，
	//     于是"文件不见了"这个判据被新的空文件掩盖，检测永远不触发（实测踩到过）。
	lostSidecars = missingSidecarPaths(path, existedSidecars, movedSidecars)
	s3, err3 := openOnce(path)
	if err3 != nil {
		// 留档已经发生（主库改名成功、路径上可能已被 PRAGMA 建出一个 0 字节文件），
		// 这时**必须把留档路径写进错误**：0 字节文件在 sqlite 眼里是合法空库，
		// 下次启动 openOnce 会成功、note=""，用户拿到一个空库却没有任何线索指向
		// `.corrupt-*`。把落点钉在错误文本里，用户至少还找得到旧数据。
		// lostSidecars 也要带上（在 openOnce 之前算好了）：这条失败出口和第三步的
		// note 是同一类出口，同样不能把"驱动把 -wal 删了"这条信息吞掉。
		return nil, "", rebuildFailedError(backup, err3, lostSidecars)
	}
	return s3, "数据库已损坏（未通过完整性检查），原文件已留档为 " + backup +
		"，现在使用的是新建的空库。旧数据的恢复请从留档文件入手，不要删除它。" +
		movedSidecarText(movedSidecars, "另有副文件也已移到 ") +
		sidecarFailText(sidecarErrs) +
		lostSidecarNote(lostSidecars), nil
}

// rebuildFailedError 拼"留档成功、但原路径新建空库失败"这句错误。
//
// 单独拆出来是为了能被测试直接验：这条分支在 Windows 上没法端到端造出来
// （试过的造法都先在 rename 那一步失败），而"错误里必须带留档路径"是这条修复的
// 全部价值 —— 用户下次启动只会看到一个"一切正常的空库"，唯一的线索就是这句话。
//
// lost 是"在打开/留档过程中被驱动删掉的副文件"（可能为空）：这条失败出口与第三步
// 成功的 note 是同一类出口，同样不能把"可能含着全部已提交数据的 -wal 已经没了"
// 吞掉（复审 H1 的形态在这条出口上一样成立）。
func rebuildFailedError(backup string, cause error, lost []string) error {
	return fmt.Errorf("数据库已损坏，原文件已留档为 %s，但在该路径新建空库失败: %w"+
		"；留档文件请保留（旧数据都在它和它旁边的 .stale-* 里）%s", backup, cause, lostSidecarNote(lost))
}

// corruptArchiveSuffix 是"留档文件"的名字后缀（`<db>.corrupt-<stamp>`）。
const corruptArchiveSuffix = ".corrupt-"

// archivedLibraryNote 在"当前库是空的、旁边却躺着一份 `.corrupt-*` 留档"时
// 给出提示；其余情况返回空串。
//
// 这条是复审 P2-4 的真实形态：留档重建**成功**之后，note 只在当时那个会话里
// 出现过一次；下次启动 openOnce 成功、note 为空串，用户看到的是"一切正常"，
// 而他的目标 / 连接历史 / 核查报告其实都在旁边那份 `.corrupt-*` 里。
// 实测（造一个坏库 → OpenDetail 走完留档重建 → 关掉再 OpenDetail）：
// 修复前第二次的 note 恰好是空串，用户没有任何线索。
//
// **只在库空着的时候说**：设计上明确要求用户"保留"那份留档文件，所以它会一直
// 躺在数据目录里；不做这个限制的话，每个恢复过的用户此后每次启动都会被念一遍。
// 库里一旦有用户自己的数据（目标、连接、核查报告……），就说明他已经用起来了，
// 不再提示。
func archivedLibraryNote(s *Store, path string) string {
	newest, ok := newestCorruptArchive(path)
	if !ok {
		return ""
	}
	if !s.libraryEmpty() {
		return ""
	}
	return "注意：这个数据库旁边有一份留档文件 " + newest + "，当前库是新建的空库。" +
		"如果你在找以前的目标、连接历史或核查报告，旧数据在留档文件里，" +
		"当前库不会再有它们 —— 请从留档文件入手恢复，不要删除它。"
}

// newestCorruptArchive 找 `<path>.corrupt-*` 里最新的那一份（没有则 false）。
//
// 留档名的 stamp 是 `20060102-150405.000000000`，字典序即时间序，所以直接取
// 最大值即可（不必依赖 mtime —— 备份还原会把 mtime 改掉）。
func newestCorruptArchive(path string) (string, bool) {
	dir := filepath.Dir(path)
	prefix := filepath.Base(path) + corruptArchiveSuffix
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	newest := ""
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		if e.Name() > newest {
			newest = e.Name()
		}
	}
	if newest == "" {
		return "", false
	}
	return filepath.Join(dir, newest), true
}

// libraryEmpty 判断库里有没有**用户自己的数据**。
//
// settings 不在判据里：它一定会有行（Close 写的 last_clean_exit、用户改过的
// 选项），拿它当"用过"会让这条提示永远不触发。
// 查不动时返回 false（宁可不说，也不能凭一次读失败就下"你的库是空的"这种结论）。
func (s *Store) libraryEmpty() bool {
	for _, table := range []string{
		"targets", "connections", "db_conns", "known_hosts",
		"scan_events", "compliance_reports", "secrets",
	} {
		var one int
		if err := s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM ` + table + `)`).Scan(&one); err != nil {
			return false
		}
		if one == 1 {
			return false
		}
	}
	return true
}

// wrapLostSidecars 把"被驱动删掉的副文件"与"改名失败的原因"接进错误链。
//
// 为什么这两件事必须进 error：用户手里只有一句 `file is not a database`，
// 它既不提旁边那个装着全部已提交数据的 -wal 已经没了（该去备份里找），
// 也不提某个副文件改名失败（还挂在原路径上、别当垃圾删了）。
func wrapLostSidecars(original error, lost []string, moved []movedSidecar, moveErr error) error {
	if len(lost) > 0 {
		original = fmt.Errorf("%w（重试打开时驱动已删除 %s：请保留 %s，"+
			"主库里可能是旧数据、真正的最新数据在副文件里）",
			original, strings.Join(lost, "、"),
			orNoneText(movedDestinations(moved), "数据库目录里的留档文件"))
	}
	if moveErr != nil {
		// 以前 moveErr 只当布尔用，改名失败的原因从不进用户文本。
		original = fmt.Errorf("%w（另有副文件没能移到一边：%v；它可能还挂在原路径上，"+
			"请保留、不要删除）", original, moveErr)
	}
	return original
}

// lostSidecarNote 把"打开/留档过程中被数据库驱动删掉的副文件"拼成给用户看的
// 一段 note（空列表返回空串）。
//
// 为什么不能只靠 wrapLostSidecars：那个函数接的是 **error 链**，只在 OpenDetail
// 失败时才有机会被用户看到；而第三步（留档 + 新建）**成功**时走的是 note，
// 两者是两条独立的出口。实测形态：主库是 21 字节垃圾 + 旁边一份 39 字节非空
// -wal，驱动在建连接时就把 -wal 删了，于是 note 里只有"已留档为 .corrupt-*"，
// 一个字都不提那份**可能含着全部已提交数据**的 -wal —— 用户不会去备份里找。
//
// 措辞与成功路径的 discardedDataSidecarPaths 警告保持一致（都是"可能含着全部
// 已提交的数据"），但用"删除"而不是"丢弃"：这条路径已经做了留档重建，
// 说的是驱动删文件这件事本身。
func lostSidecarNote(lost []string) string {
	if len(lost) == 0 {
		return ""
	}
	return " **注意**：在打开/留档过程中，数据库驱动删除了这些副文件：" +
		strings.Join(lost, "、") + "。它们里面**可能含着全部已提交的数据**" +
		"（不只是未提交的事务），主库文件本身可能是旧的。" +
		"请立即停止写入（每次写入都在覆盖仅存的旧数据），先把这个库文件另存一份，" +
		"再从备份里找回这些副文件重试。"
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
// 两个都要：给用户的文本要报 Dst（他去哪里找），而 missingSidecarPaths 判断
// "驱动删了没"要拿 Src 与移走清单对照 —— 只有 Dst 的话，字符串对不上，
// 我们亲手移走的文件会被误报成"驱动删掉了"。
type movedSidecar struct {
	Src string
	Dst string
}

// sidecarFile 是"打开数据库之前"旁边那份副文件的记录：路径与当时的大小。
//
// 大小是必须的：空 -wal（0 字节）被驱动删掉是**正常**的（里面本来没有帧），
// 而**非空** -wal 被删掉意味着可能丢了已提交的数据。只记后缀的话两者分不开，
// 要么漏报真丢数据，要么每个正常库都吓用户一次。
type sidecarFile struct {
	Path string // 完整路径（path + ext）
	Size int64
}

// sidecarSnapshot 记录 `path` 旁边当前存在哪些副文件（用于事后判断"被删了"）。
//
// 必须在**第一次打开之前**调用：sqlite 会在打开过程中删除它丢弃的副文件，
// 打开之后再 Stat 就分不清"本来没有"与"被驱动丢了"。
func sidecarSnapshot(path string) []sidecarFile {
	var out []sidecarFile
	for _, ext := range []string{"-wal", "-shm"} {
		p := path + ext
		if st, err := os.Stat(p); err == nil {
			out = append(out, sidecarFile{Path: p, Size: st.Size()})
		}
	}
	return out
}

// missingSidecarPaths 从"打开之前存在过"的快照里挑出**现在真的没了**的那些。
//
// 为什么要单独查一遍：sqlite 驱动在打开（无论成功还是失败）时可能已经把副文件
// 删掉（实测：主库不是数据库 + 有 -wal 时，报 `file is not a database (26)` 的
// 同时副文件消失）。这属于**数据丢失**，必须写进交出去的文本里 —— 用户手里
// 只有一句"file is not a database"，他不会知道旁边那个装着最新数据的 -wal 已经
// 没了，也就不会去备份里找。
//
// 我们自己移走的（moved 里列出的）不算被删 —— 文件名对不上就会把亲手搬走的
// 文件误报成驱动删除。
func missingSidecarPaths(path string, existed []sidecarFile, moved []movedSidecar) []string {
	movedSrc := map[string]bool{}
	for _, m := range moved {
		movedSrc[m.Src] = true
	}
	var lost []string
	for _, s := range existed {
		if movedSrc[s.Path] {
			continue // 是我们自己移走的，不是被删的
		}
		if _, err := os.Stat(s.Path); err != nil {
			lost = append(lost, s.Path)
		}
	}
	return lost
}

// discardedDataSidecarPaths 是**成功路径**专用的判据：挑出"打开前非空、打开后
// 不见了、又不是我们移走的"副文件 —— 这些里面可能含着已提交的数据。
//
// 为什么不直接复用 missingSidecarPaths：正常关闭的库旁边那份 0 字节副文件被
// 驱动清掉是常态，把它也算成"丢了数据"会让每次正常启动都弹一次警告。
// 非空的才算 —— 实测的形态正是"主库 4096 字节、全部已提交数据在 12392 字节的
// -wal 里，把 -wal 覆盖成垃圾后驱动静默删掉它并打开成功"。
func discardedDataSidecarPaths(path string, existed []sidecarFile, moved []movedSidecar) []string {
	movedSrc := map[string]bool{}
	for _, m := range moved {
		movedSrc[m.Src] = true
	}
	var lost []string
	for _, s := range existed {
		if movedSrc[s.Path] || s.Size == 0 {
			continue
		}
		if _, err := os.Stat(s.Path); err != nil {
			lost = append(lost, s.Path)
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
	// DSN 里带 busy_timeout：PRAGMA 只作用于当时那条连接，连接被换掉就失效，
	// 写进 DSN 才可靠（见 dsn）。
	db, err := sql.Open("sqlite", dsn(path))
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

// dsn 给数据库路径拼上 DSN 级 PRAGMA。
//
// 为什么不能只在打开时 `Exec("PRAGMA ...")`：那些 PRAGMA 只作用于**当时那条
// 连接**。busy_timeout / foreign_keys 都是**连接级**设置，database/sql 一旦因为
// "连接坏了"或回收把连接换掉，新连接上就退回默认值（busy_timeout=0 → 一撞锁
// 立刻报 SQLITE_BUSY；foreign_keys=OFF）。写进 DSN，驱动每次建连接都会执行。
// 用户给的路径里一般没有 `?`（Windows 路径不会），所以直接拼。
func dsn(path string) string {
	return dsnWithBusyTimeout(path, defaultBusyTimeoutMS)
}

// defaultBusyTimeoutMS 是常规连接等待写锁的毫秒数（写进 DSN，见 dsn）。
const defaultBusyTimeoutMS = 5000

// dsnWithBusyTimeout 与 dsn 相同，但可以指定 busy_timeout（毫秒）。
//
// 单独留一个可调超时的入口，是给**关库路径**用的（见 writeLastCleanExit）：
// busy_timeout 是连接级设置，在 s.db 上 Exec 一条 PRAGMA 改不动"以后新建的连接"，
// 而关库那次写入要的是一个**确定的**上界，不能跟着 DSN 里那 5 秒走。
// （Win 路径不含 `?`，与 dsn 一样直接拼。）
func dsnWithBusyTimeout(path string, ms int) string {
	return fmt.Sprintf("%s?_pragma=busy_timeout(%d)&_pragma=foreign_keys(1)", path, ms)
}

// openOnce 是一次纯粹的打开尝试（不做任何补救）。
func openOnce(path string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn(path))
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
	return &Store{db: db, dbPath: path, bootAt: processBootAt()}, nil
}

// Close 关闭数据库。
//
// 关闭前写一次 last_clean_exit：MarkStaleConnections 靠它区分"上一次运行留下的
// 残留"与"另一个实例此刻正在跑的会话"—— 跨进程时 bootAt 帮不上忙（两个进程各取
// 自己的启动时刻），只有"上次干净退出的时刻"才是共同的判据。
// 写失败不影响关闭：标记只会落到"没有干净退出记录"那一路（多标几条残留），
// 绝不会少标，比因为一个时间戳写不进去就把关库整个弄失败要好。
//
// **顺序是"先写、再关句柄"**（复审 P0-2）：以前是先 s.db.Close() 再写，写的是
// 一个已经关掉的句柄 —— 必然失败、错误还被 `_ =` 吞掉。实测：Close 之后
// `SELECT value FROM settings WHERE key='last_clean_exit'` 报
// `sql: no rows in result set`，预置 value=1 再 Close 仍然是 1；也就是说库里
// 从来没有过这条记录，MarkStaleConnections 的 cutoff 恒为 0，
// "用上次干净退出的时刻区分残留"这一半判据是死的（只有 owner_pid 那一半在工作）。
//
// 顺序上的副作用也正好是想要的（复审 P2-1）：写在前，就不存在"关库报错 → 提前
// return → 连时间戳都没写"那条路 —— 那恰恰是最需要留痕的场景。而写失败**不能
// 吞**：这是排查"为什么这次重开又多了几条残留"的唯一线索。
//
// **这次写的等待有确定上界**（复审 M1）：顺序改对之后，另一个连接持写锁时
// Close 会跟着 DSN 里的 busy_timeout 一直等下去（实测阻塞 3.047s；加上
// busyRetry 最坏约 10.2s），用户点关闭后窗口要等、且没有任何反馈。标记写不进去
// 只是"下次多标几条残留"（见上），绝不该让退出路径卡住 —— 所以这次写入走
// writeLastCleanExit 里那条**短超时**连接（closeWriteBusyTimeoutMS），
// 试一次、失败就记日志继续关。
func (s *Store) Close() error {
	if err := s.writeLastCleanExit(); err != nil {
		log.Printf("写入干净退出时刻失败（下次启动会把残留会话多标几条）: %v", err)
	}
	return s.db.Close()
}

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
// "读 secret_id"与"删目标"必须在**同一条语句**里（DELETE ... RETURNING）：
// 以前是先 GetTarget（事务外读）、再开事务删，两步之间没有锁，并发的 SaveTarget
// 把 secret_id 换成新值时就会留下新的孤儿密文（目标没了、能解出明文口令的密文
// 永远没人删），或者反过来出现"目标行还在、密文已经被删"。
// 任一步失败都整体回滚并把错误交出去（以前第二次删除的错误被 `_` 吞掉）。
func (s *Store) DeleteTarget(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("删除目标失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 成功后 Rollback 返回 ErrTxDone，无害

	// RETURNING 拿到的就是这条语句删掉的那一行的 secret_id：不存在先读后写的窗口。
	var secretID string
	err = tx.QueryRow(`DELETE FROM targets WHERE id = ? RETURNING secret_id`, id).Scan(&secretID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("删除目标失败: %w", err)
	}
	if secretID != "" {
		if _, err := tx.Exec(`DELETE FROM secrets WHERE id = ?`, secretID); err != nil {
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
//
// 落库时盖上本进程的 pid：MarkStaleConnections 靠它判断"写下这条记录的程序
// 是不是还在跑"。以前只靠进程级 bootAt，两个实例共用数据目录时后启动的那个会
// 把前一个实例**正在跑**的会话标成"程序未正常退出"（实测跨进程复现）。
func (s *Store) AddConnection(rec domain.ConnectionRecord) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO connections(target_id,name,host,port,username,started_at,owner_pid)
		VALUES(?,?,?,?,?,?,?)`, rec.TargetID, rec.Name, rec.Host, rec.Port, rec.Username, rec.StartedAt, os.Getpid())
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
//
// **读错误不再被吞成默认值**：库瞬时锁住（另一个实例在写）时，老实现把"设过的
// 值"显示成"默认值"，用户在设置页看到的是假的现状。原签名保留（调用点在别的
// 包里），需要区分"没设过"与"读不到"的调用方用 GetSettingErr。
func (s *Store) GetSetting(key, def string) string {
	v, _ := s.GetSettingErr(key, def)
	return v
}

// GetSettingErr 与 GetSetting 相同，但把"库里读不出来"的错误交出去
// （行不存在仍然只返回默认值、err 为 nil —— 那不是错误）。
func (s *Store) GetSettingErr(key, def string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	if err != nil {
		return def, fmt.Errorf("读取设置 %s 失败: %w", key, err)
	}
	return v, nil
}

// PutSetting 写入一个设置项。
func (s *Store) PutSetting(key, value string) error {
	// busyRetry：另一实例刚好在这几百毫秒里持写锁时，等一次就能过去 ——
	// 以前这种瞬时 BUSY 会让整个动作直接失败（用户看到"保存失败"）。
	return busyRetry(func() error {
		_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
		if err != nil {
			return fmt.Errorf("保存设置失败: %w", err)
		}
		return nil
	})
}

// PutSettingsKV 在**一个事务**里写入多组键值（顺序即传入顺序）。
//
// 为什么需要它：设置页一次要保存 8 项，service 侧以前是逐项 PutSetting —— 中间
// 任一项写失败（库被另一实例锁住、磁盘满）时，前面的项**已经落库**，交出去的是
// "库里有新有旧、接口回 502"的混合状态；前端拿到 502 就按旧值渲染，用户下次保存
// 又把已经生效的项改回去（复审 M4 的 M4 症状）。放进一个事务之后，要么 8 项全生效，
// 要么一项都不生效，不存在中间态。
//
// busyRetry 语义与 PutSetting 完全一致（复审要求）：整批重试一次，而不是只重试
// 失败的那一条 —— 第一条 BUSY 时事务里什么都没写成，重跑整批是安全的；
// 重试前必须先让上一个事务回滚（defer tx.Rollback 在闭包返回时执行）。
// 空列表直接成功，不开事务。
func (s *Store) PutSettingsKV(pairs [][2]string) error {
	if len(pairs) == 0 {
		return nil
	}
	return busyRetry(func() error {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("保存设置失败: %w", err)
		}
		// 提交成功后 Rollback 返回 ErrTxDone，无害；失败路径靠它整体回滚。
		defer func() { _ = tx.Rollback() }()

		for _, kv := range pairs {
			if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, kv[0], kv[1]); err != nil {
				return fmt.Errorf("保存设置 %s 失败: %w", kv[0], err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("保存设置失败: %w", err)
		}
		return nil
	})
}

// PruneConnections 清理连接历史：删掉超过 keepDays 天的记录，并且只保留最近 keepMax 条。
// 两个条件任一为 0 表示该条件不启用。返回删除的行数。
//
// 两条 DELETE 在**一个事务**里：以前是两句独立 Exec，按天数那句成功、按条数那句
// 撞上 BUSY 时，前半段已经生效却返回错误 —— 调用方（main.go 的启动清理）见到 err
// 就跳过后面的事件与报告清理，于是"清了一半"，而用户看到的是"清理失败"。
func (s *Store) PruneConnections(keepDays, keepMax int) (int64, error) {
	if keepDays <= 0 && keepMax <= 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("清理连接历史失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 成功后 Rollback 返回 ErrTxDone，无害

	var removed int64
	if keepDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -keepDays).UnixMilli()
		res, err := tx.Exec(`DELETE FROM connections WHERE started_at < ?`, cutoff)
		if err != nil {
			return 0, fmt.Errorf("清理过期连接历史失败: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	if keepMax > 0 {
		res, err := tx.Exec(`DELETE FROM connections WHERE id NOT IN (
			SELECT id FROM connections ORDER BY started_at DESC LIMIT ?)`, keepMax)
		if err != nil {
			return 0, fmt.Errorf("清理超额连接历史失败: %w", err)
		}
		n, _ := res.RowsAffected()
		removed += n
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("清理连接历史失败: %w", err)
	}
	return removed, nil
}

// lastCleanExitKey 是 settings 里记"上次干净退出的时刻"（Unix 毫秒）的键。
// Close 写它，MarkStaleConnections 读它。
const lastCleanExitKey = "last_clean_exit"

// ownerAlive 是"写下这条记录的进程还在不在"的判据，做成变量是为了测试能注入。
//
// owner_pid 为 0 表示是老库的残留记录（那时还没这一列），无从判断进程，
// 只能退回到"本进程启动之前开始的就算残留"这个旧判据。
var ownerAlive = processAlive

// openOnceSucceededHook 是**测试注入点**（生产路径恒为 nil，声明必须在非 _test.go
// 文件里，否则别的包与 `go build` 都编译不过）：在 OpenDetail 第一次打开成功之后、
// 判定"丢弃副文件"之前触发一次。
//
// 为什么需要它：本机实测驱动在"垃圾 -wal + 合法主库"这种形态下会把 -wal 文件
// **留在原地**（只是不认它的内容），于是"打开前有、打开后没了"这个可观察量造不出来。
// 钩子让这条隐藏路径可以被端到端钉住：它把 -wal 挪走，等价于"驱动丢弃了它"。
var openOnceSucceededHook func(s *Store)

// MarkStaleConnections 把"没有结束时间"的连接记录标记为中断。
// 程序被强杀、崩溃或断电时会留下这种记录（ended_at = 0），启动时清理一次，
// 避免历史里永远挂着"进行中"。
//
// 判据（**跨进程自适应**）：一条 ended_at=0 的记录算"上次运行的残留"，当且仅当
//
//   - 写下它的进程已经不在（owner_pid 那个 pid 查不到）；或
//   - 那条记录没有 owner_pid（老库残留），且是**本进程启动之前**开始的、
//     又**晚于本库上次干净退出的时刻**（没有干净退出记录时后者不设限）。
//
// 为什么不只看 bootAt：bootAt 是**进程自己的**启动时刻，管不了别的实例。
// 实测跨进程复现：A（pid 14836）建了活连接并持续活着，B（pid 23192）2 秒后打开
// 同一个库 → A 那条 started_at < B.bootAt 的活记录被 B 标成"程序未正常退出"。
// 换成 last_clean_exit 也不够 —— B 启动那一刻 A 还没退过，库里根本没有干净退出
// 记录，判据同样退化成"bootAt 之前"。只有"那个 pid 还在不在"能分开这两种情形。
func (s *Store) MarkStaleConnections(reason string) (int64, error) {
	// cutoff = "这个库上次干净退出的时刻"：早于它开始、又还挂着的记录都已经
	// 被上一次退出处理过了，不该再动（这条判据只给没有 owner_pid 的老库记录用）。
	cutoff := int64(0)
	if clean, ok := s.lastCleanExit(); ok {
		cutoff = clean
	}
	spid := os.Getpid()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("标记中断的连接记录失败: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // 成功后 Rollback 返回 ErrTxDone，无害

	rows, err := tx.Query(`SELECT id, started_at, owner_pid FROM connections WHERE ended_at = 0`)
	if err != nil {
		return 0, fmt.Errorf("标记中断的连接记录失败: %w", err)
	}
	type openConn struct {
		id        int64
		startedAt int64
		ownerPID  int
	}
	var opens []openConn
	for rows.Next() {
		var c openConn
		if err := rows.Scan(&c.id, &c.startedAt, &c.ownerPID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("标记中断的连接记录失败: %w", err)
		}
		opens = append(opens, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("标记中断的连接记录失败: %w", err)
	}

	var marked int64
	for _, c := range opens {
		stale := false
		switch {
		case c.ownerPID == spid:
			// 本进程自己刚建的会话：绝不能标
		case c.ownerPID != 0:
			// 别的进程写的：它还在就算"正在进行"，它没了就是残留
			stale = !ownerAlive(c.ownerPID)
		default:
			// 老库没有 owner_pid：退回"本进程启动之前开始 + 晚于上次干净退出"。
			// 没有干净退出记录时（上次是崩溃结束的）只看 bootAt 这一条。
			stale = c.startedAt < s.bootAt && (cutoff == 0 || c.startedAt > cutoff)
		}
		if !stale {
			continue
		}
		if _, err := tx.Exec(`UPDATE connections SET ended_at = started_at, exit_code = 1, error = ?
			WHERE id = ?`, reason, c.id); err != nil {
			return 0, fmt.Errorf("标记中断的连接记录失败: %w", err)
		}
		marked++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("标记中断的连接记录失败: %w", err)
	}
	return marked, nil
}

// lastCleanExit 读"上次干净退出的时刻"。第二个返回值 false 表示库里没有记录
// （全新库、或上一次运行是崩溃/强杀结束的）。
func (s *Store) lastCleanExit() (int64, bool) {
	raw, err := s.GetSettingErr(lastCleanExitKey, "")
	if err != nil || strings.TrimSpace(raw) == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

// writeLastCleanExit 记下本库"干净退出"的时刻。
//
// **每次都写是有意的**（复审 P2-2）：这里以前有一道"只在值真的变化时写"的守卫，
// 但它永远为假 —— `ts := now()` 每次都是新的毫秒值，`old == ts` 不可能成立，
// 所以它实际上每次 Close 都写库，注释承诺的行为从来没发生过。留着那道守卫比
// 删掉更坏：下一个人会以为"这里已经省掉了一次写"。
//
// 为什么不去实现一个"距上次超过 N 秒才写"的真守卫：这个字段记的就是"这一刻库
// 被干净关掉了"，写旧值会把 cutoff 往前挪，反而让残留判据变松（cutoff 越小，
// 越多的老记录会被判成"晚于上次干净退出"而标脏）。一次 Close 只写一行，且马上
// 就要关库，这次写本来就该发生。
//
// **用另一条短超时连接写，不走 s.PutSetting**（复审 M1）：s.db 的 DSN 带
// busy_timeout=5000，另一个实例持写锁时这次写会等满 5 秒（PutSetting 的
// busyRetry 再加一次 → 最坏约 10.2s），而它后面就是 s.db.Close() ——
// 退出路径被一个"写不进去也只是多标几条残留"的标记拖住，用户点关闭后没有任何
// 反馈。这里单开一条连接的三个理由：
//
//  1. busy_timeout 是**连接级**设置，在 s.db 上 Exec 一条 PRAGMA 只改到当时
//     那条连接（池子里换一条就失效，见 dsn 的说明）；只有写进 DSN，
//     "这一次写的上界"才是确定的。
//  2. 不动 s.db 的连接，就不会给它留下一个被改小过的 busy_timeout ——
//     Close 失败被重试、或 Store 还要再用一会儿时，主连接的语义不能被改。
//  3. 只试一次、不重试：这是关库路径，宁可放弃这次标记（退回"没有干净退出记录"
//     那一路，只会多标几条残留）也不拖时间。注意这条取舍也覆盖"本进程刚好还有
//     一次写在跑"的情形（那时写锁在 s.db 手里）：等 200ms 也拿不到就放弃 ——
//     标记丢了的代价只是"下次多标几条残留"，而多等 5 秒的代价是退出路径卡住。
func (s *Store) writeLastCleanExit() error {
	db, err := sql.Open("sqlite", dsnWithBusyTimeout(s.dbPath, closeWriteBusyTimeoutMS))
	if err != nil {
		return fmt.Errorf("打开关库路径的连接失败: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`INSERT INTO settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		lastCleanExitKey, strconv.FormatInt(now(), 10)); err != nil {
		return fmt.Errorf("写入干净退出时刻失败: %w", err)
	}
	return nil
}

// closeWriteBusyTimeoutMS 是关库那次 last_clean_exit 写入允许等待的毫秒数。
//
// 200ms 只够覆盖"另一实例刚好在写"这种瞬时窗口：等不到就放弃标记、照常关库
// （只会在下次启动多标几条残留，见 Close）。**不能**用 DSN 里的 5000 ——
// 那正是 M1 里"点关闭要等 3~10 秒"的来源。上界 = 这个值 + 一次连接建立的开销，
// 远小于"退出路径必须快速返回"的 1 秒要求。
const closeWriteBusyTimeoutMS = 200

// migrate 为老库补新增列（SQLite 不支持 ADD COLUMN IF NOT EXISTS，先查 PRAGMA）。
func migrate(db *sql.DB) error {
	// 结构版本先比后迁：用比库更老的程序打开被新版迁移过的库时，必须明确拒绝，
	// 而不是照常打开、照常写，然后按自己的理解解释新数据（以前 PRAGMA
	// user_version 完全没用上，这条路全程没有任何提示）。0 表示"还没写过版本"
	// （全新库或老库），照常往下迁移。
	var ver int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		return fmt.Errorf("读取库结构版本失败: %w", err)
	}
	if ver > schemaVersion {
		return fmt.Errorf("数据库结构版本 %d 比本程序认识的 %d 更新："+
			"请用更新版本的 awdshell 打开（用旧版本继续写会破坏新数据）", ver, schemaVersion)
	}
	// 版本号只在**真的不一样**时才写：写上它是写事务，无条件写的话另一实例
	// 持写锁时启动会卡满 busy_timeout（实测把 user_version 写进 openOnce 之后
	// TestM3CleanStartupSkipsMigrationUnderWriteLock 立刻红了）——
	// "启动不该为了什么都没改的元数据去抢写锁"。
	if ver != schemaVersion {
		if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
			return fmt.Errorf("写入库结构版本失败: %w", err)
		}
	}

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

	// 连接历史的 owner_pid 列（v2 新增）：跨进程时"写下这条记录的进程还在不在"
	// 才是判断活会话的真判据，见 MarkStaleConnections。
	connCols, err := tableColumns(db, "connections")
	if err != nil {
		return fmt.Errorf("读取连接历史表结构失败: %w", err)
	}
	if !connCols["owner_pid"] {
		if _, err := db.Exec(`ALTER TABLE connections ADD COLUMN owner_pid INTEGER NOT NULL DEFAULT 0`); err != nil {
			// 与 start_dir 同理：另一个实例可能已经加好了
			if !isDuplicateColumn(err) {
				return fmt.Errorf("迁移 owner_pid 列失败: %w", err)
			}
		}
	}

	// 核查报告的秒级时间戳迁移。
	//
	// 放在这里而不是 ensureComplianceReports：那个函数原来带包级 sync.Once，
	// scope 是"进程"而不是"这个库"——同一进程里第二次打开别的库就不会再迁移
	// （-web 与桌面模式并存、或将来任何两个 Store 指向同一个 .db 都会踩到）。
	// 建表已经在 schema 里（每次 Open 都跑），所以这里可以直接 UPDATE。
	//
	// **先查有没有行要改**：以前每次启动都无条件发这条 UPDATE，于是另一个实例
	// 持写锁时，后启动的那个要等满 busy_timeout 然后以
	// 「迁移核查报告时间戳失败: database is locked (5)」启动失败（实测 5074ms），
	// 而且错误文案指向"迁移失败"，看不出是被人锁了一下。没有行要改的库
	// （绝大多数）现在连写事务都不开。
	if err := migrateIfNeeded(db, "迁移核查报告时间戳失败",
		`SELECT 1 FROM compliance_reports WHERE ts >= 946684800 AND ts < 4102444800 LIMIT 1`,
		complianceTSMigration); err != nil {
		return err
	}

	// 主机密钥的秒级时间戳迁移（同 complianceTSMigration 的理由：老库的秒值
	// 不加迁移会按毫秒解释成 1970-01-21）。known_hosts 已经建在 schema 里。
	if err := migrateIfNeeded(db, "迁移主机密钥时间戳失败",
		`SELECT 1 FROM known_hosts WHERE (first_seen >= 946684800 AND first_seen < 4102444800)
		   OR (last_seen  >= 946684800 AND last_seen  < 4102444800) LIMIT 1`,
		hostKeyTSMigration); err != nil {
		return err
	}
	return nil
}

// tableColumns 返回一张表当前已有的列名集合。
func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		have[name] = true
	}
	return have, rows.Err()
}

// migrateIfNeeded 先跑 probe 判断有没有行要改，没有就整条跳过。
//
// probe 是**只读**查询（不取写锁），所以另一个实例持写锁时它照样能跑完 ——
// 这正是要的效果：启动不该为了"什么都没改"的迁移去抢写锁。
func migrateIfNeeded(db *sql.DB, opName, probe, update string) error {
	var one int
	err := db.QueryRow(probe).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // 没有行要改，跳过（不开写事务）
	}
	if err != nil {
		return fmt.Errorf("%s: %w", opName, err)
	}
	// 确实有行要改：这里才去抢写锁，并给 BUSY 一次短延时重试的机会 ——
	// 另一实例正好在写时，等一瞬就能过去，不必让整个启动失败。
	if err := busyRetry(func() error {
		_, err := db.Exec(update)
		return err
	}); err != nil {
		return fmt.Errorf("%s: %w", opName, err)
	}
	return nil
}

// busyRetryDelay 是 BUSY 之后重试前的等待时间。200ms 只够覆盖"另一实例刚好
// 在写"这种瞬时窗口；真被长时间锁住说明对面在跑长事务，交给调用方报错更诚实。
const busyRetryDelay = 200 * time.Millisecond

// busyRetry 跑一次写操作，撞上 SQLITE_BUSY 就短延时后重试一次。
//
// 为什么要它：另一实例持写锁时，以前启动路径会等满 busy_timeout 然后**直接
// 失败**（实测「迁移核查报告时间戳失败: database is locked (5)」5074ms 后
// 退出，程序起不来）。一次重试能覆盖绝大多数"别人刚好在写"的情形。
func busyRetry(fn func() error) error {
	err := fn()
	if !isBusy(err) {
		return err
	}
	time.Sleep(busyRetryDelay)
	return fn()
}

// isBusy 判断错误是不是 SQLITE_BUSY（database is locked）。
//
// 用驱动的 *sqlite.Error 取结果码，而不是只匹配错误字符串：字符串是给用户看的
// 文案，可能被包一层或改措辞；结果码才是判据。取不到码时退回小写子串匹配，
// 保证被包装过的错误（database/sql 会包一层）也能认出来。
func isBusy(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_BUSY {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "sqlite_busy")
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

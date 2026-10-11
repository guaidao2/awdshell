package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/guaidao2/awdshell/internal/infra/sftpx"
	"github.com/guaidao2/awdshell/internal/infra/sshx"

	"golang.org/x/crypto/ssh"
)

// FileService 提供远程文件操作（SFTP），复用连接池里的同一条 SSH 连接。
type FileService struct {
	targets *TargetService
	pool    *sshx.Pool
}

// NewFileService 构造服务。
func NewFileService(targets *TargetService, pool *sshx.Pool) *FileService {
	return &FileService{targets: targets, pool: pool}
}

const trashDirName = ".awdshell-trash"

// withClient 借出一条 SFTP 通道执行操作；**只有连接类**错误才丢弃池中连接。
//
// 为什么不再无条件 Drop：`sftpx.New` 失败最常见的原因是远端 sshd **没开 sftp 子系统**
// （`ssh: subsystem request failed`）—— 那是子系统级失败，底层连接完全健康。
// 无条件 Drop 会把用户正在用的终端一起掐断（实测同一 client 上的 `NewSession()`
// 从成功变成 `use of closed network connection`）；而且这类失败是恒定属性，
// 重连也解决不了，只会每次再掐一次。
func (s *FileService) withClient(targetID string, fn func(*sftpx.Client) error) error {
	target, auth, err := s.targets.Auth(targetID)
	if err != nil {
		return err
	}
	key := poolKey(targetID)
	conn, err := s.pool.Acquire(key, func() (*ssh.Client, error) {
		return sshx.Dial(target.Host, target.Port, auth, 12*time.Second)
	})
	if err != nil {
		return err
	}

	cl, err := sftpx.New(conn)
	if err != nil {
		// **子系统建不出来不算连接坏**：`ssh: subsystem request failed` 说明远端
		// sshd 没开 sftp，底层 SSH 连接完全健康 —— 重连也解决不了，只会把用户
		// 正在用的终端一起掐断（这类失败是恒定属性，每次开文件面板都会再掐一次）。
		//
		// 注意这里**不能**复用 sshx.IsConnError：它的判据是"排除 ExitError/
		// OpenChannelError/ExitMissingError 之后一律 true"，而 SFTP 的普通错误
		//（路径不存在、权限不足）正好落进默认分支 —— 等于无条件 Drop。
		if !isSFTPSubsystemError(err) && looksLikeBrokenConn(err) {
			s.pool.DropIf(key, conn)
		}
		return err
	}
	defer cl.Close()

	// 整个 SFTP 会话算一次"长连接引用"：>5 分钟的大文件上传不该被 reaper 按空闲回收
	release := s.pool.Hold(conn)
	defer release()

	if err := fn(cl); err != nil {
		// 只有"连接确实坏了"才摘掉池连接；SFTP 的路径/权限错误不能算
		//（否则用户点一个已删除的文件就会掐断终端共用连接）。
		if looksLikeBrokenConn(err) {
			s.pool.DropIf(key, conn)
		}
		return err
	}
	return nil
}

// isSFTPSubsystemError 判断错误是不是"远端 sshd 没开 sftp 子系统"。
//
// 这类失败与连接健康无关（底层 channel 是好的），必须与"连接坏了"分开 ——
// 拿它去 Drop 会把终端共用连接掐断，而重连也解决不了（sshd 配置不会变）。
func isSFTPSubsystemError(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())
	return strings.Contains(low, "subsystem request failed") ||
		strings.Contains(low, "subsystem") && strings.Contains(low, "failed")
}

// looksLikeBrokenConn 判断 SFTP 错误是不是连接层面的故障。
//
// 不能只看子串：错误消息里带着远端路径，对 /etc/nginx/closed.conf、
// /tmp/eof-test.sh 这类路径操作失败会被误判成连接故障，进而 Drop 掉
// 终端共用的那条连接。所以先排除明确的"文件/权限"类错误，再看连接特征。
func looksLikeBrokenConn(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())

	// 这些是文件或权限问题，跟连接无关
	for _, k := range []string{"no such file", "not exist", "permission denied", "is a directory",
		"not a directory", "file exists", "no space", "read-only file system", "operation not permitted"} {
		if strings.Contains(low, k) {
			return false
		}
	}
	// 再看连接类特征。**只用高置信度的整词/前缀**：
	// `eof`、`connection` 这类太泛 —— 远端路径本身就能带出来。
	// 实测 `open /home/u/closed.log: EOF`、`open /var/log/geofencing.log: EOF`
	// 都被误判成连接故障，进而 Drop 掉终端共用的那条连接。
	for _, k := range []string{
		"ssh: ", "broken pipe", "connection reset by peer", "connection refused",
		"use of closed network connection", "session closed", "channel closed",
		"i/o timeout", "no route to host", "network is unreachable",
	} {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}

// List 列出目录内容。
func (s *FileService) List(targetID, dir string) ([]sftpx.Entry, error) {
	out := []sftpx.Entry{}
	err := s.withClient(targetID, func(c *sftpx.Client) error {
		list, err := c.List(dir)
		if err != nil {
			return err
		}
		out = list
		return nil
	})
	return out, err
}

// Home 返回默认目录（家目录）。
func (s *FileService) Home(targetID string) (string, error) {
	home := "/"
	err := s.withClient(targetID, func(c *sftpx.Client) error {
		h, err := c.Home()
		if err != nil {
			return err
		}
		home = h
		return nil
	})
	return home, err
}

// Mkdir 创建目录（递归）。
func (s *FileService) Mkdir(targetID, p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("路径不能为空")
	}
	return s.withClient(targetID, func(c *sftpx.Client) error { return c.Mkdir(p) })
}

// Rename 重命名或移动。
func (s *FileService) Rename(targetID, oldPath, newPath string) error {
	if strings.TrimSpace(oldPath) == "" || strings.TrimSpace(newPath) == "" {
		return fmt.Errorf("路径不能为空")
	}
	return s.withClient(targetID, func(c *sftpx.Client) error { return c.Rename(oldPath, newPath) })
}

// protectedPaths 是拒绝删除的系统关键目录。
// 删文件是不可逆操作（回收站可能因跨分区失败），递归删掉 /etc 或 /usr 等于把机器废掉。
var protectedPaths = map[string]bool{
	"/": true, "/bin": true, "/sbin": true, "/lib": true, "/lib32": true, "/lib64": true,
	"/usr": true, "/etc": true, "/boot": true, "/dev": true, "/proc": true, "/sys": true,
	"/var": true, "/home": true, "/root": true, "/opt": true, "/srv": true, "/run": true,
}

// checkDeletePath 校验一条待删除路径，返回 Clean 后的路径。
//
// 两条判据：
//
//  1. **相对路径里的上跳（`..` / `../..` / `../../etc`）一律拒绝**。
//     保护表只覆盖绝对路径，而保护表里的条目都是 `/etc` 这种写法 ——
//     相对路径既不在表里，又由 SFTP 服务端按"登录后的当前目录"解析，
//     于是 `paths:["../.."]` 能一路跳到父目录、再被递归删掉。UI 走的都是
//     绝对路径，所以拒掉相对上跳不影响任何正常操作。
//  2. 去掉 `.` / `..` 与重复斜杠之后命中保护表的一律拒绝。
func checkDeletePath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || p == "." {
		return "", fmt.Errorf("路径不合法")
	}
	// 只看开头那几段：`../x`、`../..`、`..\x`（远端可能是 Windows OpenSSH）
	// 都要挡。不去动 `..foo` 这种正常的文件名 —— 它不是上跳。
	norm := strings.ReplaceAll(p, "\\", "/")
	if norm == ".." || strings.HasPrefix(norm, "../") {
		return "", fmt.Errorf("拒绝相对路径的上跳（请用绝对路径）")
	}
	clean := path.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("拒绝相对路径的上跳（请用绝对路径）")
	}
	if protectedPaths[clean] {
		return "", fmt.Errorf("系统关键目录，拒绝删除（这条限制是为了防止误操作把目标机废掉）")
	}
	return clean, nil
}

// DeleteResult 是一次批量删除的结果：逐条成功/失败，而不是一个笼统的 error。
type DeleteResult struct {
	Deleted []string        `json:"deleted"`
	Failed  []DeleteFailure `json:"failed"`
}

// DeleteFailure 是删除失败的某条路径。
type DeleteFailure struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

// ErrDeleteNoPaths 表示"没有指定要删除的路径"。
//
// 为什么要一个哨兵值：它表达的是**请求不完整**（HTTP 400），而 Delete 的其余
// 错误都是连接/远端故障（502）。以前控制面拿不到这个区分，一律回 502 ——
// 实测 POST /api/files/delete {} 得到 502 Bad Gateway（审计 M3）。
var ErrDeleteNoPaths = errors.New("没有指定要删除的路径")

// errDeleteNoPaths 是与 ErrDeleteNoPaths **不同值**的同胞错误。
//
// 为什么要两个：Delete 返回的一直是 ErrDeleteNoPaths（对外契约），而这个私有值
// 存在的意义是让"返回的错误到底是不是哨兵本身"变成一个**可测的**判据 ——
// Go 对 `errors.New("同样的字面量")` 与 `fmt.Errorf("无格式串")` 都会复用内部
// 实例（实测：两者与调用点的字面量是同一个指针），于是"改回返回临时错误"
// 这种回归在没有这个对照值的时候测不出来。
var errDeleteNoPaths = errors.New("没有指定要删除的路径（内部：不指定路径）")

// Delete 删除路径。trash=true 时移入远端回收站（同分区 rename），更安全。
//
// **逐条执行、逐条报告**：以前遇到第一个错误就 return，于是"部分成功"只回一个
// 错误，调用方无从得知哪些已经删掉。实测删 `[a.txt, missing.txt, c.txt]` 返回
// `路径不存在`，但 a.txt 已被**永久删除**、c.txt 还在；`[important.txt, /]` 因为
// 后面是受保护路径而整批报错，可 important.txt 已经没了。
//
// 另外把"建回收站目录"从校验之前**推迟到第一条真正要删的路径**：以前路径非法
// 导致整批中止时，远端已经留下一个空的 `.awdshell-trash/<时间戳>-<rand>/`。
func (s *FileService) Delete(targetID string, paths []string, trash bool) (DeleteResult, error) {
	res := DeleteResult{Deleted: []string{}, Failed: []DeleteFailure{}}
	if len(paths) == 0 {
		return res, ErrDeleteNoPaths
	}

	// 先做纯本地校验：非法路径直接记失败，不碰远端、也不建回收站目录
	type job struct{ clean string }
	jobs := make([]job, 0, len(paths))
	for _, p := range paths {
		trimmed := strings.TrimSpace(p)
		clean, err := checkDeletePath(trimmed)
		if err != nil {
			res.Failed = append(res.Failed, DeleteFailure{Path: trimmed, Error: err.Error()})
			continue
		}
		jobs = append(jobs, job{clean})
	}
	if len(jobs) == 0 {
		return res, nil // 全被校验挡下：是"逐条失败"，不是连接错误
	}

	err := s.withClient(targetID, func(c *sftpx.Client) error {
		var trashRoot string
		if trash {
			home, err := c.Home()
			if err != nil || home == "" || home == "/" {
				return fmt.Errorf("拿不到远程家目录，为安全起见取消删除（回收站会建错位置）")
			}
			// 目录名带一个随机后缀：同一秒内移入多个同名文件时，
			// 只精确到秒的目录名会让后一个 rename 覆盖前一个，静默丢数据。
			trashRoot = path.Join(home, trashDirName, time.Now().Format("20060102-150405")+"-"+randSuffix())
		}
		trashReady := false

		for _, j := range jobs {
			if trash {
				if !trashReady {
					if err := c.Mkdir(trashRoot); err != nil {
						res.Failed = append(res.Failed, DeleteFailure{
							Path: j.clean, Error: "创建回收站目录失败: " + err.Error()})
						continue
					}
					trashReady = true
				}
				// 目标名撞了要换名，见 uniqueTrashDest。
				dest, err := uniqueTrashDest(c, trashRoot, j.clean)
				if err != nil {
					res.Failed = append(res.Failed, DeleteFailure{Path: j.clean, Error: err.Error()})
					continue
				}
				if err := c.Rename(j.clean, dest); err != nil {
					res.Failed = append(res.Failed, DeleteFailure{
						Path: j.clean, Error: "移入回收站失败（可能跨分区）: " + err.Error()})
					continue
				}
				res.Deleted = append(res.Deleted, j.clean)
				continue
			}
			if err := c.Remove(j.clean, true); err != nil {
				res.Failed = append(res.Failed, DeleteFailure{Path: j.clean, Error: err.Error()})
				continue
			}
			res.Deleted = append(res.Deleted, j.clean)
		}
		return nil
	})
	if err != nil {
		return res, err // 连接级错误（withClient 内部已按连接类判过 Drop）
	}
	return res, nil
}

// trashExister 只取 uniqueTrashDest 需要的那一件事：目标名是否已被占用。
//
// 之所以抽出这么小的接口：回收站取名这条逻辑（同批同名不互相覆盖）必须能被
// 单元测试直接钉住 —— 而 sftpx.Client 需要一条真的 SFTP 通道才构造得出来。
type trashExister interface {
	Lstat(p string) (sftpx.Entry, error)
}

// uniqueTrashDest 给一条待移入回收站的路径挑一个**没被占用**的目标名。
//
// **为什么不直接用 path.Base(clean)**：同一批里 /a/x.txt 与 /b/x.txt 的
// path.Base 都是 x.txt，两个 rename 打到回收站的同一个路径上 —— 后一个覆盖前一个，
// 回收站里少一个文件，而用户以为已经保住了。判据是"远端此刻是否已存在"
// （前一次 rename 成功后目标就在那儿了），所以同批内的撞名也会被让开，
// 不需要另记一张表。后缀插在扩展名之前，形如 `x (1).txt`。
func uniqueTrashDest(remote trashExister, trashRoot, src string) (string, error) {
	base := path.Base(src)
	if base == "" || base == "." || base == "/" {
		base = "deleted"
	}
	ext := path.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	// 点文件（`.bashrc`）的 path.Ext 会把整个名字当扩展名，stem 变成空串 ——
	// 于是后缀生成出 `" (1).bashrc"`（前导空格、点没了）。这种情况整体当 stem。
	if stem == "" {
		stem = base
		ext = ""
	}
	for i := 0; i < 1000; i++ {
		name := base
		if i > 0 {
			name = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		dest := path.Join(trashRoot, name)
		// Lstat：不能跟随符号链接。目标名指着已有文件/目录都要让位。
		if _, err := remote.Lstat(dest); err != nil {
			return dest, nil
		}
	}
	return "", fmt.Errorf("回收站里同名文件太多，请先清理回收站")
}

// randSuffix 生成一小段随机串，用于回收站目录名去重。
func randSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// 拿不到随机数时退回纳秒时间戳，至少不会与同秒的另一批同名
		return fmt.Sprintf("%d", time.Now().UnixNano()%100000)
	}
	return hex.EncodeToString(b)
}

// Download 把远程文件写到 w。
func (s *FileService) Download(targetID, remotePath string, w io.Writer) error {
	return s.withClient(targetID, func(c *sftpx.Client) error {
		f, err := c.Raw().Open(remotePath)
		if err != nil {
			return fmt.Errorf("打开文件失败: %w", err)
		}
		defer f.Close()
		_, err = io.Copy(w, f)
		return err
	})
}

// DownloadToDir 把远端文件下载到本地目录，返回实际写入的绝对路径。
//
// 与 Download 的区别：这个直接落到用户配好的目录，不交给浏览器 ——
// 浏览器下载只能落到系统默认下载目录，选不了地方。
//
// 两个安全处理：
//   - 文件名只取最后一段并滤掉路径分隔符，远端路径里的 ../ 不能把文件写到目录之外；
//   - 用 O_EXCL 抢文件名，同名自动加序号，不覆盖用户已有的东西（并发下也不会互相覆盖）。
func (s *FileService) DownloadToDir(targetID, remotePath, dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", fmt.Errorf("没有配置默认下载目录")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建下载目录失败: %w", err)
	}
	f, local, err := createExclusive(dir, safeLocalName(path.Base(remotePath)))
	if err != nil {
		return "", err
	}

	if err := s.Download(targetID, remotePath, f); err != nil {
		// 先关句柄再删：Windows 上句柄没关时 os.Remove 会失败
		//（"being used by another process"），半截文件会顶着最终名留下来，
		// 下次下载还会因为"已存在"被改成 (1)。
		f.Close()
		_ = os.Remove(local)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(local)
		return "", fmt.Errorf("写入本地文件失败: %w", err)
	}
	return local, nil
}

// safeLocalName 把远端文件名变成安全的本地文件名。
//
// 远端文件名是对方机器上的东西，不能直接拿来拼本地路径：
// 里面可能有 ../、绝对路径、Windows 保留字符或控制字符。
func safeLocalName(name string) string {
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 0x7f {
			return -1
		}
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return '_'
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	// Windows 上以点结尾、以及 . / .. 这类都不合法
	name = strings.TrimRight(name, ". ")
	if name == "" {
		name = "download"
	}
	// 保留设备名要加前缀：直接叫 NUL 的话会写到设备上，报成功但磁盘没文件
	if isReservedDeviceName(name) {
		name = "_" + name
	}
	return name
}

// Upload 是 Stage + Commit 的组合，供内容已经在内存里的调用方使用
// （编辑器保存）。verify 在改名之前调用，返回错误就放弃这次上传。
//
// 流式上传（HTTP 请求体）请直接用 StageUpload/CommitUpload ——
// 那样才能把"请求体是否完整"也并进判断，见 StageUpload 的说明。
func (s *FileService) Upload(targetID, remotePath string, r io.Reader, verify func() error) (int64, error) {
	tmp, n, err := s.StageUpload(targetID, remotePath, r)
	if err != nil {
		return n, err
	}
	if verify != nil {
		if err := verify(); err != nil {
			_ = s.AbortUpload(targetID, tmp)
			return n, err
		}
	}
	if err := s.CommitUpload(targetID, tmp, remotePath); err != nil {
		return n, err
	}
	return n, nil
}

// StageUpload 把 r 写到远端的**临时文件**，返回临时路径与字节数。
//
// 刻意不动 remotePath：调用方要等确认**整个请求体都收全了**再调 CommitUpload。
// 边读边覆盖同名文件是不行的 —— 客户端中途断开时 multipart 的 part 会"正常"
// 读到 EOF 而不报错，等发现时为时已晚（实测会在远端留下 100KB 的半截文件
// 顶着最终名字，而接口只回一个错误）。
//
// 临时文件带随机后缀：并发上传同一个目标时彼此不踩。
func (s *FileService) StageUpload(targetID, remotePath string, r io.Reader) (string, int64, error) {
	var n int64
	var tmp string
	err := s.withClient(targetID, func(c *sftpx.Client) error {
		if dir := path.Dir(remotePath); dir != "" && dir != "." {
			// MkdirAll 对"已存在"是幂等的，所以这里能报出来的都是真错误
			//（权限不足、磁盘满、父路径是文件）。以前吞掉它，后面 Create 会
			// 报一个看不出真因的 "no such file"。
			if err := c.Mkdir(dir); err != nil {
				return fmt.Errorf("创建远端目录 %s 失败: %w", dir, err)
			}
		}
		var rb [8]byte
		if _, err := rand.Read(rb[:]); err != nil {
			return fmt.Errorf("生成临时文件名失败: %w", err)
		}
		tmp = remotePath + ".awdshell-part-" + hex.EncodeToString(rb[:])

		f, err := c.Raw().Create(tmp)
		if err != nil {
			tmp = "" // 让调用方拿到空串，别去 abort 一个根本没建起来的路径
			return fmt.Errorf("创建远程文件失败: %w", err)
		}
		n, err = io.Copy(f, r)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			// 写失败：立刻清掉临时文件，远端原文件一个字节都没动
			_ = c.Raw().Remove(tmp)
			tmp = ""
			return err
		}
		return nil
	})
	return tmp, n, err
}

// CommitUpload 把暂存的临时文件**原子改名**到目标路径。
//
// OpenSSH 的 Rename 在目标已存在时会失败，所以优先用 posix-rename 扩展
// （原子替换）；服务端不支持时退回"先删后改名"，中间窗口极小。
func (s *FileService) CommitUpload(targetID, tmp, remotePath string) error {
	return s.withClient(targetID, func(c *sftpx.Client) error {
		// 先看目标现在的状态，两件事都靠它：
		// ① 是**目录**就不能覆盖 —— 下面的回退会把空目录删掉（pkg/sftp 服务端
		//    的 REMOVE 用 os.Remove，OpenSSH 的 sftp-server 对 REMOVE 也有 rmdir
		//    回退），结果是"上传一个文件，毁掉一个目录"；
		// ② 记下原文件权限，改名后套回去 —— 先建临时文件再 rename 会替换 inode，
		//    客户端 open 不带 attrs、服务端默认 0644，于是 600 的 .env、
		//    authorized_keys、私钥被同名覆盖后会静默变成 0644。
		var oldMode os.FileMode
		hasOld := false
		if fi, err := c.Raw().Lstat(remotePath); err == nil {
			if fi.IsDir() {
				_ = c.Raw().Remove(tmp)
				return fmt.Errorf("%w: %s", ErrTargetIsDir, remotePath)
			}
			// 符号链接不套权限：改链接的 mode 在 Linux 上基本是 no-op
			if fi.Mode()&os.ModeSymlink == 0 {
				oldMode = fi.Mode()
				hasOld = true
			}
		}
		if err := c.Raw().PosixRename(tmp, remotePath); err != nil {
			// 退回路径：服务端不支持 posix-rename（OpenSSH 的 Rename 在目标已存在时
			// 会失败），只能用"撤走旧的 → 放上新的"两步。
			//
			// **旧文件必须改名到 .bak，不能先 Remove**：以前是先删再改名，第二步
			// 若也失败（权限、磁盘满、连接断），原文件已经没了 —— 新内容还在 tmp 里，
			// 用户手里两份都不在正确位置，而错误提示只说"临时文件保留可重试"。
			// 改名到 .bak 之后，失败时原文件**原样可恢复**。
			var backup string
			if _, statErr := c.Raw().Lstat(remotePath); statErr == nil {
				// 目标存在：先改名到备份名。改名和删除一样可能失败（目录不可写），
				// 那就如实报错并清掉 tmp —— 原文件分毫未动。
				var rb [4]byte
				if _, rerr := rand.Read(rb[:]); rerr != nil {
					_ = c.Raw().Remove(tmp)
					return fmt.Errorf("替换远端文件失败（服务端不支持原子改名，且生成备份名失败）: %w", err)
				}
				backup = remotePath + ".awdshell-bak-" + hex.EncodeToString(rb[:])
				if mvErr := c.Raw().Rename(remotePath, backup); mvErr != nil {
					_ = c.Raw().Remove(tmp)
					return fmt.Errorf("替换远端文件失败（无法把原文件挪到备份名）: %w", mvErr)
				}
			}
			// 目标不存在（新建文件）时不必备份，直接改名。
			if err2 := c.Raw().Rename(tmp, remotePath); err2 != nil {
				if backup != "" {
					// 把原文件搬回去：能搬回去就什么都不丢。
					if backErr := c.Raw().Rename(backup, remotePath); backErr != nil {
						return fmt.Errorf("改名失败（原文件已备份为 %s，可手动改名恢复；新内容保留在 %s）: %w",
							backup, tmp, err2)
					}
					_ = c.Raw().Remove(tmp)
					return fmt.Errorf("改名失败，原文件已恢复（内容未改动）: %w", err2)
				}
				// 没有原文件可恢复（本来就是新建）：保留 tmp 让调用方重试
				return fmt.Errorf("改名失败（临时文件保留在 %s，可重试）: %w", tmp, err2)
			}
			// 新文件已经就位，备份名可以清了；清不掉不算失败（文件是好的）
			if backup != "" {
				_ = c.Raw().Remove(backup)
			}
		}
		if hasOld {
			if err := c.Raw().Chmod(remotePath, oldMode); err != nil {
				// 不吞错：覆盖 .env / authorized_keys 时权限没恢复是静默降级
				return fmt.Errorf("文件已上传，但恢复原权限失败（现为服务端默认权限）: %w", err)
			}
		}
		return nil
	})
}

// ErrTargetIsDir 表示上传目标是一个目录（不能覆盖）。
// 单独定义是为了让 HTTP 层回 400 而不是 502 —— 那是客户端的路径问题，不是服务端故障。
var ErrTargetIsDir = errors.New("远端目标是一个目录，不能覆盖")

// AbortUpload 删掉暂存但没能落地的临时文件。
func (s *FileService) AbortUpload(targetID, tmp string) error {
	if tmp == "" {
		return nil
	}
	return s.withClient(targetID, func(c *sftpx.Client) error {
		return c.Raw().Remove(tmp)
	})
}

// TextMaxBytes 是内置编辑器能打开的文件上限。
// 这个值同时决定前端是否显示「编辑」按钮，只留这一个来源 ——
// 之前后端截断在 256KB、前端按 1MB 判断，中间区间的文件点开拿到的是被截断的内容，
// 一保存就把远端文件截短了。
const TextMaxBytes = 256 * 1024

// Chmod 修改远程路径权限；mode 是八进制字符串，如 "644"、"755"、"4755"。
//
// 查后门、修被改成 777 的目录、给脚本加执行位，这些事以前只能切回终端做。
func (s *FileService) Chmod(targetID, remotePath, mode string) error {
	mode = strings.TrimSpace(mode)
	if !regexp.MustCompile(`^[0-7]{3,4}$`).MatchString(mode) {
		return fmt.Errorf("权限要写成 3 到 4 位八进制数，例如 644、755、4755")
	}
	bits, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return fmt.Errorf("权限解析失败：%s", mode)
	}
	return s.withClient(targetID, func(c *sftpx.Client) error {
		if err := c.Chmod(remotePath, os.FileMode(bits)); err != nil {
			return fmt.Errorf("修改权限失败: %w", err)
		}
		return nil
	})
}

// ReadText 读取文本文件（编辑器预览用）。
// 超过上限时报错，**不返回截断内容**。
func (s *FileService) ReadText(targetID, remotePath string, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = TextMaxBytes
	}
	content := ""
	err := s.withClient(targetID, func(c *sftpx.Client) error {
		// 先按大小拦一道，省得白读一遍
		if st, err := c.Raw().Stat(remotePath); err == nil && st.Size() > maxBytes {
			return fmt.Errorf("文件有 %s，超过编辑器上限 %s：请下载后用本地工具编辑",
				humanSize(st.Size()), humanSize(maxBytes))
		}
		f, err := c.Raw().Open(remotePath)
		if err != nil {
			return fmt.Errorf("打开文件失败: %w", err)
		}
		defer f.Close()
		// 多读一个字节，用于 Stat 拿不到大小时的兜底判断
		buf, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
		if err != nil {
			return err
		}
		if int64(len(buf)) > maxBytes {
			return fmt.Errorf("文件超过编辑器上限 %s：请下载后用本地工具编辑", humanSize(maxBytes))
		}
		if looksBinary(buf) {
			return fmt.Errorf("这是二进制文件，内置编辑器打不开（请下载后用本地工具处理）")
		}
		content = string(buf)
		return nil
	})
	return content, err
}

// EnsureReadableFile 在下载前先确认远端路径存在且是普通文件。
// 响应头一旦发出就没法再改成错误了，用户只会拿到一个 0 字节文件并以为下载成功。
func (s *FileService) EnsureReadableFile(targetID, remotePath string) error {
	return s.withClient(targetID, func(c *sftpx.Client) error {
		st, err := c.Raw().Stat(remotePath)
		if err != nil {
			return fmt.Errorf("读不到这个文件（不存在或当前账号没有权限）：%s", remotePath)
		}
		if st.IsDir() {
			return fmt.Errorf("这是目录，不能直接下载：%s", remotePath)
		}
		return nil
	})
}

// humanSize 把字节数写成易读形式（错误提示里用）。
func humanSize(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	v := float64(n)
	for i := 0; i < len(units); i++ {
		v /= 1024
		if v < 1024 || i == len(units)-1 {
			return fmt.Sprintf("%.1f %s", v, units[i])
		}
	}
	return fmt.Sprintf("%d B", n)
}

// looksBinary 粗略判断二进制内容：出现 NUL 字节即认为不是文本。
// 扫描上限 64KB：以前只看前 8KB，8KB 之后才有 NUL 的文件会被当文本打开，
// 编辑器保存后二进制就被破坏了（低概率但不可逆）。
func looksBinary(b []byte) bool {
	limit := len(b)
	if limit > 64*1024 {
		limit = 64 * 1024
	}
	for i := 0; i < limit; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

// WriteText 覆盖写入文本文件。
// 内容已经在内存里（编辑器保存），不需要完整性校验，所以 verify 传 nil。
func (s *FileService) WriteText(targetID, remotePath, content string) error {
	_, err := s.Upload(targetID, remotePath, strings.NewReader(content), nil)
	return err
}

// StartDirInfo 描述目标的有效起始目录。
type StartDirInfo struct {
	Path     string `json:"path"`     // 实际可用的目录
	Source   string `json:"source"`   // configured（用了配置值）| home（没配置）| fallback（配置了但不可用）
	Wanted   string `json:"wanted"`   // 目标里配置的原始值，便于 UI 提示
	Fallback bool   `json:"fallback"` // 是否发生了回退
}

// ResolveStartDir 计算目标真正可用的起始目录：
// 优先用目标配置的 start_dir，但要求它存在且是目录；否则优雅回退到 SSH 默认（家目录）。
// 终端与文件面板共用这一处判断，避免两边行为不一致。
func (s *FileService) ResolveStartDir(targetID string) (StartDirInfo, error) {
	info := StartDirInfo{}
	target, err := s.targets.store.GetTarget(targetID)
	if err != nil {
		return info, err
	}
	info.Wanted = strings.TrimSpace(target.StartDir)

	err = s.withClient(targetID, func(c *sftpx.Client) error {
		home, err := c.Home()
		if err != nil {
			return err
		}
		if info.Wanted == "" {
			info.Path = home
			info.Source = "home"
			return nil
		}
		if st, err := c.Stat(info.Wanted); err == nil && st.IsDir {
			info.Path = info.Wanted
			info.Source = "configured"
			return nil
		}
		info.Path = home
		info.Source = "fallback"
		info.Fallback = true
		return nil
	})
	return info, err
}

// cwdProbe 精确定位"我们这条 SSH 连接上那个交互 shell"的当前目录：
// 探测通道自己的父进程就是这个会话的 sshd，交互 shell 与它同父，于是不会被别的会话干扰。
// 只读，不改目标机任何状态。
const cwdProbe = `m=$PPID; for p in $(ps -eo pid=,ppid=,tty=,comm= 2>/dev/null | awk -v m=$m '$2==m && $3 ~ /pts/ && $4 ~ /^(bash|zsh|sh|dash|fish)$/ {print $1}'); do readlink /proc/$p/cwd 2>/dev/null; done | head -n 1`

// TermCwd 通过同一条 SSH 连接探测交互终端的当前目录（供文件面板"同步终端目录"使用）。
func (s *FileService) TermCwd(targetID string) (string, error) {
	target, auth, err := s.targets.Auth(targetID)
	if err != nil {
		return "", err
	}
	key := poolKey(targetID)
	conn, err := s.pool.Acquire(key, func() (*ssh.Client, error) {
		return sshx.Dial(target.Host, target.Port, auth, 12*time.Second)
	})
	if err != nil {
		return "", err
	}
	out, err := sshx.RunOutput(conn, cwdProbe, 8*time.Second)
	if err != nil {
		// 探测脚本自己失败（没匹配到交互 shell、ppid 对不上等）不代表连接坏了。
		// 丢弃共享连接会连带掐断用户正在用的终端。
		if sshx.IsConnError(err) {
			s.pool.DropIf(key, conn) // 按身份删，别误删别人刚换上的那条
		}
		return "", fmt.Errorf("探测终端目录失败: %w", err)
	}
	if out == "" {
		return "", fmt.Errorf("没能定位到终端目录：请先在这台主机上打开一个终端，再点同步")
	}
	return out, nil
}

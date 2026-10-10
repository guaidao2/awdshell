package service

import (
	"crypto/rand"
	"encoding/hex"
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

// withClient 借出一条 SFTP 通道执行操作；连接类错误会丢弃池中连接以便下次重连。
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
		s.pool.Drop(key)
		return err
	}
	defer cl.Close()

	if err := fn(cl); err != nil {
		if looksLikeBrokenConn(err) {
			s.pool.Drop(key)
		}
		return err
	}
	return nil
}

func looksLikeBrokenConn(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, k := range []string{"connection", "eof", "closed", "broken pipe", "reset by peer", "ssh:"} {
		if strings.Contains(msg, k) {
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

// Delete 删除路径。trash=true 时移入远端回收站（同分区 rename），更安全。
func (s *FileService) Delete(targetID string, paths []string, trash bool) error {
	if len(paths) == 0 {
		return fmt.Errorf("没有指定要删除的路径")
	}
	return s.withClient(targetID, func(c *sftpx.Client) error {
		var trashRoot string
		if trash {
			home, err := c.Home()
			if err != nil || home == "" || home == "/" {
				return fmt.Errorf("拿不到远程家目录，为安全起见取消删除（回收站会建错位置）")
			}
			// 目录名带一个随机后缀：同一秒内移入多个同名文件时，
			// 只精确到秒的目录名会让后一个 rename 覆盖前一个，静默丢数据。
			trashRoot = path.Join(home, trashDirName, time.Now().Format("20060102-150405")+"-"+randSuffix())
			if err := c.Mkdir(trashRoot); err != nil {
				return fmt.Errorf("创建回收站目录失败: %w", err)
			}
		}
		for _, p := range paths {
			p = strings.TrimSpace(p)
			if p == "" || p == "." {
				return fmt.Errorf("拒绝对 %q 执行删除", p)
			}
			clean := path.Clean(p)
			if protectedPaths[clean] {
				return fmt.Errorf("拒绝删除系统关键目录 %s（这条限制是为了防止误操作把目标机废掉）", clean)
			}
			if trash {
				dest := path.Join(trashRoot, path.Base(clean))
				if err := c.Rename(clean, dest); err != nil {
					return fmt.Errorf("移入回收站失败（可能跨分区）%s: %w", clean, err)
				}
				continue
			}
			if err := c.Remove(clean, true); err != nil {
				return err
			}
		}
		return nil
	})
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

// Upload 把 r 写入远程路径，返回字节数。
func (s *FileService) Upload(targetID, remotePath string, r io.Reader) (int64, error) {
	var n int64
	err := s.withClient(targetID, func(c *sftpx.Client) error {
		if dir := path.Dir(remotePath); dir != "" && dir != "." {
			_ = c.Mkdir(dir)
		}
		f, err := c.Raw().Create(remotePath)
		if err != nil {
			return fmt.Errorf("创建远程文件失败: %w", err)
		}
		defer f.Close()
		n, err = io.Copy(f, r)
		return err
	})
	return n, err
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

// looksBinary 粗略判断二进制内容：前 8KB 出现 NUL 字节即认为不是文本。
func looksBinary(b []byte) bool {
	limit := len(b)
	if limit > 8192 {
		limit = 8192
	}
	for i := 0; i < limit; i++ {
		if b[i] == 0 {
			return true
		}
	}
	return false
}

// WriteText 覆盖写入文本文件。
func (s *FileService) WriteText(targetID, remotePath, content string) error {
	_, err := s.Upload(targetID, remotePath, strings.NewReader(content))
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
		s.pool.Drop(key)
		return "", fmt.Errorf("探测终端目录失败: %w", err)
	}
	if out == "" {
		return "", fmt.Errorf("没能定位到终端目录：请先在这台主机上打开一个终端，再点同步")
	}
	return out, nil
}

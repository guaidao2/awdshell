// Package sftpx 封装 SFTP 文件操作。
package sftpx

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Client 是一条 SFTP 通道。
type Client struct {
	sc *sftp.Client
}

// New 在已有 SSH 连接上开一条 SFTP 通道。
func New(conn *ssh.Client) (*Client, error) {
	sc, err := sftp.NewClient(conn)
	if err != nil {
		return nil, fmt.Errorf("打开 SFTP 通道失败: %w", err)
	}
	return &Client{sc: sc}, nil
}

// Close 关闭通道（不关闭底层 SSH 连接）。
func (c *Client) Close() error { return c.sc.Close() }

// Entry 是一个文件/目录条目。
type Entry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	IsDir   bool   `json:"is_dir"`
	IsLink  bool   `json:"is_link"`
	ModTime int64  `json:"mod_time"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
}

// Raw 暴露底层客户端（上传下载等流式操作使用）。
func (c *Client) Raw() *sftp.Client { return c.sc }

// Home 返回登录后的默认目录（通常即家目录）。
func (c *Client) Home() (string, error) {
	wd, err := c.sc.Getwd()
	if err != nil {
		return "/", nil
	}
	return wd, nil
}

// List 列出目录内容（目录在前，名称排序）。
func (c *Client) List(dir string) ([]Entry, error) {
	if dir == "" {
		dir = "."
	}
	infos, err := c.sc.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("读取目录失败: %w", err)
	}
	out := make([]Entry, 0, len(infos))
	for _, fi := range infos {
		e := entryOf(dir, fi)
		out = append(out, e)
	}
	sortEntries(out)
	return out, nil
}

// Stat 取单个路径信息。
func (c *Client) Stat(p string) (Entry, error) {
	fi, err := c.sc.Stat(p)
	if err != nil {
		return Entry{}, fmt.Errorf("读取文件信息失败: %w", err)
	}
	return entryOf(path.Dir(p), fi), nil
}

func entryOf(dir string, fi os.FileInfo) Entry {
	e := Entry{
		Name:    fi.Name(),
		Path:    path.Join(dir, fi.Name()),
		Size:    fi.Size(),
		Mode:    fi.Mode().String(),
		IsDir:   fi.IsDir(),
		IsLink:  fi.Mode()&os.ModeSymlink != 0,
		ModTime: fi.ModTime().UnixMilli(),
	}
	if st, ok := fi.Sys().(*sftp.FileStat); ok {
		e.UID = st.UID
		e.GID = st.GID
	}
	return e
}

// Mkdir 创建目录（递归）。
func (c *Client) Mkdir(p string) error {
	if err := c.sc.MkdirAll(p); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	return nil
}

// Remove 删除文件或空目录；目录递归删除由调用方决定策略。
func (c *Client) Remove(p string, recursive bool) error {
	fi, err := c.sc.Stat(p)
	if err != nil {
		return fmt.Errorf("路径不存在: %w", err)
	}
	if fi.IsDir() {
		if recursive {
			if err := c.sc.RemoveAll(p); err != nil {
				return fmt.Errorf("删除目录失败: %w", err)
			}
			return nil
		}
		if err := c.sc.RemoveDirectory(p); err != nil {
			return fmt.Errorf("删除目录失败（非空目录需递归删除）: %w", err)
		}
		return nil
	}
	if err := c.sc.Remove(p); err != nil {
		return fmt.Errorf("删除文件失败: %w", err)
	}
	return nil
}

// Rename 重命名或移动。
func (c *Client) Rename(oldPath, newPath string) error {
	if err := c.sc.Rename(oldPath, newPath); err != nil {
		return fmt.Errorf("重命名失败: %w", err)
	}
	return nil
}

// Chmod 修改权限。
func (c *Client) Chmod(p string, mode os.FileMode) error {
	if err := c.sc.Chmod(p, mode); err != nil {
		return fmt.Errorf("修改权限失败: %w", err)
	}
	return nil
}

// TrashDir 返回"回收站"目录（删除前移入，避免误删）。
func TrashDir() string {
	return path.Join(".awdshell-trash", time.Now().Format("20060102-150405"))
}

// sortEntries 目录优先、名称不区分大小写排序。
func sortEntries(list []Entry) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].IsDir != list[j].IsDir {
			return list[i].IsDir
		}
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})
}

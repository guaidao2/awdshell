package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 本地落盘：把前端生成的内容（报告 HTML、各种 CSV）写到用户配置的下载目录。
//
// 为什么不继续交给浏览器：浏览器下载只能落到系统默认下载目录，用户选不了地方。
// 配了默认下载目录之后，所有"导出/下载"都收敛到这一条路上。

// SaveTextToDir 把一段文本写到 dir，返回实际写入的绝对路径。
//
// 与远端文件下载的区别：内容来自前端（还在内存里的字符串），只负责命名与落盘。
func SaveTextToDir(dir, name, content string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", fmt.Errorf("没有配置默认下载目录")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("创建下载目录失败: %w", err)
	}
	if strings.TrimSpace(name) == "" {
		name = "awdshell-export"
	}
	f, path, err := createExclusive(dir, safeLocalName(name))
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		_ = os.Remove(path) // 写失败就清掉，别留一个顶着最终名的空文件
		return "", fmt.Errorf("写入文件失败: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("写入文件失败: %w", err)
	}
	return path, nil
}

// createExclusive 在 dir 下为 base 抢一个尚不存在的文件名，返回已打开的文件与实际路径。
//
// 用 O_CREATE|O_EXCL 而不是"先 Stat 再 Create"：后者是 TOCTOU ——
// 并发时（双击导出按钮就是两次请求）两个请求会拿到同一个名字，
// 一个把另一个的结果覆盖掉，而且两边都报成功。实测 8 个并发只剩 1 个文件。
// O_EXCL 由操作系统保证只有一方能创建成功。
//
// 名字按 Windows 的单文件名上限截断：超长名会让 Create 报 ERROR_INVALID_NAME，
// 那既不是"已存在"也不是成功，会被下面的循环当成被占用而空转一万次。
func createExclusive(dir, base string) (*os.File, string, error) {
	ext := truncateRunes(filepath.Ext(base), 20)
	stem := truncateRunes(strings.TrimSuffix(base, filepath.Ext(base)), 120)
	if stem == "" {
		stem = "download"
	}
	for i := 0; i < 10000; i++ {
		// 注意第一次也要用截断后的名字 —— 直接用超长原名的话，
		// Create 报的是 ERROR_INVALID_NAME（不是"已存在"），会被下面的判断
		// 当成硬错误立刻返回，等于超长名永远存不下来。
		name := stem + ext
		if i > 0 {
			name = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		path := filepath.Join(dir, name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			return f, path, nil
		}
		// 只有"名字被占"才换下一个序号；名字非法之类的要立刻报错，别空转
		if !isNameTaken(err) {
			return nil, "", fmt.Errorf("创建文件失败: %w", err)
		}
	}
	return nil, "", fmt.Errorf("同名文件太多，请换个文件名或清理下载目录")
}

// windowsReservedNames 是 Windows 的保留设备名。
//
// 纯 "NUL" 最坑：它会被当成设备打开，Create 与 Write 都"成功"，
// 但磁盘上什么都没有 —— 用户拿到 200 与一个不存在的文件路径。
var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// isReservedDeviceName 判断基名（去掉扩展名）是不是 Windows 保留设备名。
func isReservedDeviceName(name string) bool {
	base := name
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return windowsReservedNames[strings.ToUpper(strings.TrimSpace(base))]
}

// isNameTaken 判断创建失败是不是"这个名字被占了"，值得换下一个序号再试。
//
// os.IsExist 认不出"目标是同名目录"（Windows 报 "is a directory"），
// 而那种情况很现实：远端有个叫 logs 的文件，本地下载目录里正好有个 logs 目录。
func isNameTaken(err error) bool {
	if os.IsExist(err) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "is a directory")
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

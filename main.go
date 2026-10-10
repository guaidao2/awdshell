// awdshell 桌面主程序入口。
//
// 默认形态：Wails v2 原生窗口（内嵌前端资源 //go:embed → 单个可执行文件）。
// 进程内同时跑两件事：
//  1. 原生窗口（Wails）+ 内嵌前端资源，并动态注入 /runtime.js 把数据服务地址告诉前端；
//  2. 本地数据服务：只监听 127.0.0.1 的随机端口，提供控制面 HTTP（/api/*）与数据面 WebSocket（/ws/term/*）。
//
// 终端字节流之所以走独立端口的 WebSocket 而不走 Wails 绑定/事件：高频字节流过 JS 桥会成为瓶颈（见 docs/DESIGN.md ADR-001）。
//
// 另提供 -web 模式：不开原生窗口，只起本地服务并打开系统浏览器。用于无图形环境的服务器，或前端调试。
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/guaidao2/awdshell/internal/httpapi"
	"github.com/guaidao2/awdshell/internal/infra/logscan"
	"github.com/guaidao2/awdshell/internal/infra/sshx"
	"github.com/guaidao2/awdshell/internal/secret"
	"github.com/guaidao2/awdshell/internal/service"
	"github.com/guaidao2/awdshell/internal/store"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

const version = "0.1.0-alpha"

func main() {
	dataDir := flag.String("data", defaultDataDir(), "数据目录（数据库与凭据密钥）")
	webMode := flag.Bool("web", false, "浏览器模式：不开原生窗口，只起本地服务并打开默认浏览器")
	openBrowser := flag.Bool("open", true, "浏览器模式下是否自动打开系统浏览器")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}

	st, err := store.Open(filepath.Join(*dataDir, "awdshell.db"))
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	vault, err := secret.New(*dataDir)
	if err != nil {
		log.Fatalf("初始化凭据保险库失败: %v", err)
	}

	// 连接池：同一目标只握手一次，终端 / 文件 / 监控共用同一条 SSH 连接的不同 channel。
	pool := sshx.NewPool(5 * time.Minute)
	defer pool.CloseAll()

	settingsSvc := service.NewSettingsService(st)
	targets := service.NewTargetService(st, vault)
	sessions := service.NewSessionService(st, targets, pool)
	files := service.NewFileService(targets, pool)
	monitor := service.NewMonitorService(targets, pool)
	logs := service.NewLogScanService(targets, pool, st)
	comp := service.NewComplianceService(targets, pool, st)
	threat := service.NewThreatService(st)

	// 上次若是被强杀或崩溃，会留下"没有结束时间"的记录，启动时先标记为中断。
	// 规则库加载情况如实打到日志：哪些规则没生效、哪些变换没实现，一眼能看见
	logscan.LogRuleReport()

	if n, err := st.MarkStaleConnections("程序未正常退出"); err == nil && n > 0 {
		log.Printf("已标记 %d 条中断的连接记录", n)
	}

	// 连接历史保留策略来自设置页（默认 90 天 / 最近 500 条，0 表示不限）。
	prune := func() {
		cfg := settingsSvc.Get()
		n, err := st.PruneConnections(cfg.ConnKeepDays, cfg.ConnKeepMax)
		if err != nil {
			log.Printf("清理连接历史失败: %v", err)
			return
		}
		if n > 0 {
			log.Printf("已清理 %d 条过期连接历史", n)
		}
		// 攻击事件同样按保留期清理，避免态势库无限增长
		if _, err := threat.PruneEvents(cfg.EventKeepDays); err != nil {
			log.Printf("清理攻击事件失败: %v", err)
		}
	}
	prune()
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			prune()
		}
	}()

	assetsFS, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		log.Fatalf("加载前端资源失败: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("监听本地端口失败: %v", err)
	}
	apiBase := "http://" + ln.Addr().String()
	sessions.WSBase = "ws://" + ln.Addr().String()

	// 主机密钥校验（accept-new）：首次连接记录指纹，之后指纹变更直接拒绝连接，
	// 避免中间人无感接管。确认对端换过密钥时可在目标编辑里清除记录。
	sshx.SetHostKeyVerifier(targets)

	// 控制面令牌：随机生成、注入给页面，前端每个请求都带上。
	// 用它取代"猜桌面 WebView 的 Origin"——猜错就是整个桌面形态被自己挡在门外。
	// 顺带也让本机其它进程难以直接调用控制面。
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		log.Fatalf("生成控制面令牌失败: %v", err)
	}
	apiToken := hex.EncodeToString(tokenBytes)

	deps := httpapi.Deps{
		Targets:    targets,
		Sessions:   sessions,
		Files:      files,
		Monitor:    monitor,
		Logs:       logs,
		Compliance: comp,
		Threat:     threat,
		Settings:   settingsSvc,
		Store:      st,
		Version:    version,
		APIBase:    apiBase,
		APIToken:   apiToken,
	}

	if *webMode {
		deps.Assets = assetsFS
		runWebMode(ln, httpapi.New(deps), apiBase, *dataDir, *openBrowser, sessions)
		return
	}

	// 数据服务（控制面 + 数据面）
	apiSrv := &http.Server{Handler: httpapi.New(deps).Handler()}
	go func() {
		if err := apiSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("本地数据服务退出: %v", err)
		}
	}()

	err = wails.Run(&options.App{
		Title:     "awdshell",
		Width:     1360,
		Height:    860,
		MinWidth:  960,
		MinHeight: 600,
		AssetServer: &assetserver.Options{
			Assets: assets,
			Middleware: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// 端口是随机的，运行期注入给前端。令牌一起注入：
					// 前端每个请求带上它就不必再猜桌面 WebView 的 Origin 是什么。
					if r.URL.Path == "/runtime.js" {
						w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
						w.Header().Set("Cache-Control", "no-store")
						fmt.Fprintf(w, "window.__AWDSHELL__ = { apiBase: %q, version: %q, token: %q };\n",
							apiBase, version, apiToken)
						return
					}
					next.ServeHTTP(w, r)
				})
			},
		},
		BackgroundColour: &options.RGBA{R: 15, G: 17, B: 21, A: 1},
		OnShutdown: func(ctx context.Context) {
			sessions.CloseAll()
			pool.CloseAll()
			_ = apiSrv.Close()
		},
	})
	if err != nil {
		log.Fatalf("启动界面失败: %v", err)
	}
}

// runWebMode 以浏览器模式运行（无原生窗口）。
func runWebMode(ln net.Listener, srv *httpapi.Server, apiBase, dataDir string, open bool, sessions *service.SessionService) {
	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("本地服务退出: %v", err)
		}
	}()

	url := "http://" + ln.Addr().String()
	fmt.Printf("awdshell %s（浏览器模式）\n", version)
	fmt.Printf("  界面地址 : %s\n", url)
	fmt.Printf("  数据目录 : %s\n", dataDir)
	fmt.Println("  按 Ctrl+C 退出")
	if open {
		openURL(url)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	sessions.CloseAll()
	_ = httpSrv.Close()
}

func defaultDataDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "awdshell")
	}
	return filepath.Join(".", "data")
}

func openURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("打开浏览器失败（请手动访问 %s）: %v", url, err)
	}
}

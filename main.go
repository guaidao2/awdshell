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
	"runtime/debug"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/guaidao2/awdshell/internal/httpapi"
	"github.com/guaidao2/awdshell/internal/infra/logscan"
	"github.com/guaidao2/awdshell/internal/infra/sshx"
	"github.com/guaidao2/awdshell/internal/secret"
	"github.com/guaidao2/awdshell/internal/service"
	"github.com/guaidao2/awdshell/internal/store"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/logger"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

const version = "1.0.0"

// nowMillis 返回当前毫秒时间戳（跨边界时间戳统一用毫秒）。
func nowMillis() int64 { return time.Now().UnixMilli() }

func main() {
	// 尽早做：GUI 子系统程序不会自动附加父控制台，
	// 从命令行跑时先接上，否则参数错误、启动失败都看不到。
	attachParentConsole()
	// 代码页是**控制台**的全局状态（不是本进程的），退出时必须还回去，
	// 否则用户那个 cmd 窗口会一直停在 UTF-8，接着跑老的 GBK 程序就乱码。
	// 错误路径（flag 解析失败、panic、fatalStartup）各自显式调了一次。
	defer restoreConsoleCP()

	dataDir := flag.String("data", defaultDataDir(), "数据目录（数据库与凭据密钥）")
	webMode := flag.Bool("web", false, "浏览器模式：不开原生窗口，只起本地服务并打开默认浏览器")
	openBrowser := flag.Bool("open", true, "浏览器模式下是否自动打开系统浏览器")
	// 用 ContinueOnError 自己收尾：flag 默认在 -h / 参数错误时直接 os.Exit，
	// 那样就来不及把控制台代码页恢复回去（Init 会重置 Usage，所以要在它之后设）。
	flag.CommandLine.Init(os.Args[0], flag.ContinueOnError)
	flag.Usage = usage
	if err := flag.CommandLine.Parse(os.Args[1:]); err != nil {
		restoreConsoleCP()
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(2)
	}
	// 记下形态：fatalStartup / panic 兜底会被 HTTP handler 的 goroutine 调到，
	// 用的是 atomic 而不是普通变量（普通变量在 -race 下是数据竞争）。
	webModeFlag.Store(*webMode)

	// 启动期的 panic 也要有可见的反馈：双击运行时没有控制台，
	// 否则就是"闪一下没了"。recover 只管当前 goroutine，够兜住启动路径。
	defer func() {
		if rec := recover(); rec != nil {
			// **必须带非 0 退出码**（由 handleStartupPanic 返回）：
			// 以前 recover 之后 main 正常返回，双击或脚本拿到的都是"成功"，
			// 出没出错完全看不出来。os.Exit 不会跑 defer，
			// 所以控制台代码页是在 handleStartupPanic 里显式恢复的。
			os.Exit(handleStartupPanic(*dataDir, rec, debug.Stack()))
		}
	}()

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		fatalStartup(*dataDir, "创建数据目录失败: %v", err)
	}

	// OpenDetail：数据库损坏时会自动留档重建（只改名，不删除），
	// 并把补救说明返回回来 —— 必须弹框告诉用户，否则他看到的是"数据凭空没了"。
	st, note, err := store.OpenDetail(filepath.Join(*dataDir, "awdshell.db"))
	if err != nil {
		fatalStartup(*dataDir, "打开数据库失败: %v", err)
	}
	if note != "" {
		log.Printf("数据库补救：%s", note)
		userVisibleBox("本地数据库已重建", note, false)
	}
	defer st.Close()

	vault, err := secret.New(*dataDir)
	if err != nil {
		fatalStartup(*dataDir, "初始化凭据保险库失败: %v", err)
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
	// 数据库管理：通过已有 SSH 连接拨号到目标机上的数据库，不直连、不装 agent
	dbSvc := service.NewDatabaseService(targets, pool, st, vault)
	// 删目标时把它的数据库连接池一起关掉：只删配置的话，dbx.Conn 还活着、
	// SSH 隧道开着，`/api/db/query` 仍能对着已删目标走通。
	targets.SetOnDelete(dbSvc.DropConnsOfTarget)
	// 监控的采样基准（last / lastAt）也要跟着清：同一个 targetID 被重新添加回来时，
	// 拿着几小时前的 CPU 时间片/网卡计数当基准，算出来的百分比是假的。
	// 注意用 AddOnDelete（追加）而不是 SetOnDelete（覆盖）—— 后者会把上面那个顶掉。
	targets.AddOnDelete(monitor.Forget)

	// 上次若是被强杀或崩溃，会留下"没有结束时间"的记录，启动时先标记为中断。
	// 规则库加载情况：有规则没生效时留一行摘要，正常时不输出（细节在界面里看）
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
		// 核查报告也按保留期清理：它只写不删，否则无上限增长
		if cfg.EventKeepDays > 0 {
			if n, err := st.PruneComplianceReports(nowMillis() - int64(cfg.EventKeepDays)*24*3600*1000); err != nil {
				log.Printf("清理核查报告失败: %v", err)
			} else if n > 0 {
				log.Printf("已清理 %d 份过期核查报告", n)
			}
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
		fatalStartup(*dataDir, "加载前端资源失败: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalStartup(*dataDir, "监听本地端口失败: %v", err)
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
		fatalStartup(*dataDir, "生成控制面令牌失败: %v", err)
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
		Database:   dbSvc,
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

	// 桌面形态才有的"选目录"能力：设置页用它挑默认下载目录。
	// -web 模式没有原生对话框（deps.PickDir 保持 nil），接口会如实报错、让用户手填。
	//
	// appCtx 在 OnStartup 里才赋值，而这个闭包会被 HTTP handler 的 goroutine 调用，
	// 所以用 atomic.Value 传（普通变量是数据竞态；-race 下会报）。
	var appCtx atomic.Value
	deps.PickDir = func() (string, error) {
		ctx, _ := appCtx.Load().(context.Context)
		if ctx == nil {
			return "", fmt.Errorf("界面还没准备好，稍后再试")
		}
		return wailsruntime.OpenDirectoryDialog(ctx, wailsruntime.OpenDialogOptions{
			Title: "选择下载目录",
		})
	}

	// 数据服务（控制面 + 数据面）
	apiSrv := &http.Server{Handler: httpapi.New(deps).Handler()}
	go func() {
		if err := apiSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			// 服务挂了界面会全是 Failed to fetch，不如直接说清楚
			fatalStartup(*dataDir, "本地数据服务退出: %v", err)
		}
	}()

	// 桌面形态：日志只落文件，**不往控制台打**。
	//
	// 用户是在用图形界面，控制台里的日志对他没有意义（双击启动时压根没有控制台）；
	// 只有 -web 模式需要打印 —— 那时候他就是在终端里工作。
	//
	// 注意 Wails 内部还有若干 log.Fatal / os.Exit（窗口创建失败、WebView2 初始化
	// 失败等），它们不经过 fatalStartup，双击时又是"闪一下就没了"，
	// 所以这份日志至少保证事后能查。
	if !*webMode {
		if lf, err := os.OpenFile(filepath.Join(*dataDir, "awdshell.log"),
			os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			log.SetOutput(lf)
			defer lf.Close()
		}
	}

	err = wails.Run(&options.App{
		Title:     "awdshell",
		Width:     1360,
		Height:    860,
		MinWidth:  960,
		MinHeight: 600,
		// 默认级别会把 WebView2 的 INFO 也吐到控制台（"Environment created successfully"），
		// 对用户没有意义；只留警告及以上。
		//
		// **注意 LogLevel 只在 debug 构建里生效**：release 构建固定用
		// LogLevelProduction（默认 ERROR），所以想真正控级别得靠自定义 Logger。
		LogLevel: logger.WARNING,
		// 桌面形态让 Wails 自己的日志也落文件。
		//
		// **必须有这一行**：Wails 默认 logger 用内建 println 直接写 fd 2，
		// 既不过 log 包的 writer、也不认 os.Stderr 的替换。双击时没有控制台、
		// fd2 无效，"窗口创建失败 / WebView2 初始化失败"这类消息会彻底消失，
		// 连日志里都没有 —— 正是下面注释想避免的"闪一下就没了"。
		Logger: logger.NewFileLogger(filepath.Join(*dataDir, "awdshell.log")),
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
		OnStartup: func(ctx context.Context) {
			// 存下来给原生对话框用（deps.PickDir 那个闭包）
			appCtx.Store(ctx)
		},
		OnShutdown: func(ctx context.Context) {
			sessions.CloseAll()
			dbSvc.CloseAll()
			pool.CloseAll()
			_ = apiSrv.Close()
		},
	})
	if err != nil {
		fatalStartup(*dataDir, "启动界面失败: %v", err)
	}
}

// runWebMode 以浏览器模式运行（无原生窗口）。
func runWebMode(ln net.Listener, srv *httpapi.Server, apiBase, dataDir string, open bool, sessions *service.SessionService) {
	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() {
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			// 服务挂了就别让用户对着一个死端口等（浏览器可能已经打开了）
			fatalStartup(dataDir, "本地服务退出: %v", err)
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
	// 收尾与桌面形态保持一致：数据库连接也要关掉（它会占着共享 SSH 的隧道）
	sessions.CloseAll()
	if srv != nil && srv.Database != nil {
		srv.Database.CloseAll()
	}
	_ = httpSrv.Close()
}

// usage 打印命令行用法。
//
// Go 默认那份（"Usage of D:\...\awdshell.exe:"）对用户不友好：
// 没说这个程序是干什么的、也没给例子。
func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "awdshell %s —— 图形化的安全运维工作台\n\n", version)
	fmt.Fprintf(out, "用法：awdshell [选项]\n\n")
	fmt.Fprintf(out, "不带选项时打开图形界面。选项：\n")
	flag.PrintDefaults()
	fmt.Fprintf(out, "\n示例：\n")
	fmt.Fprintf(out, "  awdshell                      打开图形界面\n")
	fmt.Fprintf(out, "  awdshell -web                 起本地服务并用浏览器打开\n")
	fmt.Fprintf(out, "  awdshell -web -open=false     只起服务（配 -data 指定数据目录）\n")
}

// webModeFlag 记录是不是 -web 形态（原子：会被 HTTP goroutine 读）。
var webModeFlag atomic.Bool

// handleStartupPanic 兜住启动期的 panic：写日志 + 提示 + 恢复控制台代码页，
// 返回该用的进程退出码。
//
// 单独抽成一个返回值函数，是为了让"退出码不是 0"这条判据有地方钉
// （main 里就只剩 os.Exit(handleStartupPanic(...)) 这一行）。
func handleStartupPanic(dataDir string, rec any, stack []byte) int {
	msg := fmt.Sprintf("程序内部错误: %v", rec)
	log.Printf("%s\n%s", msg, stack)
	_ = writeStartupLog(dataDir, msg)
	userVisibleBox("awdshell 出错", msg, true)
	restoreConsoleCP()
	return 1
}

// userVisibleBox 决定"要不要弹原生框"。
//
// 桌面形态要弹：exe 是 GUI 子系统，双击运行时没有控制台，弹框是唯一的即时反馈。
// -web 模式不弹：用户就在终端里看着，日志已经写清楚；而 MessageBox 是**阻塞**的
// ——无头服务器上它会一直挂到有人点"确定"（那种环境根本没人点），
// "有桌面、人在终端"的会话也会被卡住。所以 web 模式只写日志。
func userVisibleBox(title, text string, isError bool) {
	if webModeFlag.Load() {
		log.Printf("%s：%s", title, text)
		return
	}
	if isError {
		showErrorBox(title, text)
		return
	}
	showNotice(title, text)
}

// fatalStartup 报告启动阶段的致命错误：写日志 + 弹原生错误框 + 退出。
//
// 为什么不能只用 log.Fatalf：exe 是 GUI 子系统，双击运行时没有控制台，
// 日志写进虚空，用户只看到程序闪一下就没了，根本不知道出了什么事。
// 所以这里把原因同时落到数据目录里的 startup-error.log 并弹框显示。
func fatalStartup(dataDir, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("启动失败: %s", msg)
	path := writeStartupLog(dataDir, msg)
	detail := ""
	if path != "" {
		detail = "\n\n详细信息见：\n" + path
	}
	userVisibleBox("awdshell 启动失败", msg+detail, true)
	restoreConsoleCP()
	os.Exit(1)
}

// writeStartupLog 把启动失败原因追加到数据目录下的日志，返回日志路径（失败返回空串）。
// 数据目录本身创建失败时不再尝试写文件，只靠弹框。
func writeStartupLog(dataDir, msg string) string {
	if strings.TrimSpace(dataDir) == "" {
		return ""
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return ""
	}
	path := filepath.Join(dataDir, "startup-error.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return ""
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), msg); err != nil {
		return "" // 写不进去就别在弹框里说"详细信息见 <path>"，那个文件是空的
	}
	return path
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

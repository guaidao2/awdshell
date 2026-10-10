// Package httpapi 提供本地控制面（HTTP JSON）与数据面（WebSocket），以及文件管理与设置接口。
//
// 在本项目的桌面形态里，静态资源由 Wails 的 AssetServer 提供，本服务只处理 /api/* 与 /ws/*，
// 监听 127.0.0.1 的随机端口；Wails WebView 属于跨源来源，因此统一加 CORS 头。
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/guaidao2/awdshell/internal/service"
	"github.com/guaidao2/awdshell/internal/store"

	"github.com/gorilla/websocket"
)

// isLocalHost 判断请求的 Host 是不是回环地址。
// 这一步防的是 DNS rebinding：攻击者把自己的域名解析到 127.0.0.1，
// 浏览器就会带着那个域名来请求本服务，光看端口拦不住。
func isLocalHost(hostport string) bool {
	// 浏览器请求一定带 Host；非浏览器来源（Wails 内部调用）可能没有，
	// 这种情况放行，否则会把桌面形态自己挡住。
	if hostport == "" {
		return true
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "127.0.0.1", "localhost", "::1", "wails.localhost":
		return true
	}
	return false
}

// isAllowedOrigin 只放行本机来源与 Wails WebView。
//
// 注意 Wails 桌面窗口在 Windows 上的页面来源是 http://wails.localhost
// （Hostname 恰好等于 wails.localhost，前面没有点），所以不能只判断
// ".wails.localhost" 后缀 —— 那样桌面形态自己会被挡在门外。
func isAllowedOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if strings.EqualFold(u.Scheme, "wails") {
		return true
	}
	hostname := strings.ToLower(u.Hostname())
	switch {
	case hostname == "wails.localhost", strings.HasSuffix(hostname, ".wails.localhost"):
		return true
	case hostname == "localhost", strings.HasSuffix(hostname, ".localhost"):
		return true
	case hostname == "::1", hostname == "[::1]":
		return true
	case hostname == "127.0.0.1", strings.HasPrefix(hostname, "127."):
		return true
	}
	return false
}

// safeFilename 去掉文件名里的控制字符，避免拼进 HTTP 头时触发 net/http 的校验 panic。
func safeFilename(name string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, name)
	if cleaned == "" {
		return "download"
	}
	return cleaned
}

// Deps 是构造 Server 需要的依赖（集中传入，避免以后每加一个服务就改签名）。
type Deps struct {
	Targets    *service.TargetService
	Sessions   *service.SessionService
	Files      *service.FileService
	Settings   *service.SettingsService
	Monitor    *service.MonitorService
	Logs       *service.LogScanService
	Compliance *service.ComplianceService
	Threat     *service.ThreatService
	Database   *service.DatabaseService
	Store      *store.Store
	Assets     fs.FS // 桌面形态下为 nil（静态资源交给 Wails）
	Version    string
	APIBase    string
	APIToken   string // 控制面令牌，注入给页面；带对令牌的请求直接放行
	// PickDir 是"选一个本地目录"的能力，由桌面形态注入（Wails 的原生目录对话框）。
	// -web 模式不设置，接口会如实报"当前形态不支持"，让用户手填路径。
	// 用函数字段而不是直接依赖 Wails 包：httpapi 不必知道界面框架是什么。
	PickDir func() (string, error)
}

// Server 是本地数据服务。
type Server struct {
	Targets    *service.TargetService
	Sessions   *service.SessionService
	Files      *service.FileService
	Settings   *service.SettingsService
	Monitor    *service.MonitorService
	Logs       *service.LogScanService
	Compliance *service.ComplianceService
	Threat     *service.ThreatService
	Database   *service.DatabaseService
	Store      *store.Store
	Assets     fs.FS
	Version    string
	APIBase    string
	APIToken   string
	// PickDir 见 Deps 里的说明
	PickDir func() (string, error)

	// stageUpload 是"把请求体里的文件暂存到远端"的可替换钩子，nil 表示用
	// Files.StageUpload。存在的唯一理由是测试：字段顺序判定（target_id / dir
	// 必须排在 file 之前）发生在暂存**之后**，不替身这一环就没法在不起 SSH
	// 的情况下测到那段逻辑。生产路径永远走 Files。
	stageUpload func(targetID, dest string, r io.Reader) (string, int64, error)

	upgrader websocket.Upgrader
}

// New 构造服务。
func New(d Deps) *Server {
	return &Server{
		Targets:    d.Targets,
		Sessions:   d.Sessions,
		Files:      d.Files,
		Settings:   d.Settings,
		Monitor:    d.Monitor,
		Logs:       d.Logs,
		Compliance: d.Compliance,
		Threat:     d.Threat,
		Database:   d.Database,
		Store:      d.Store,
		Assets:     d.Assets,
		Version:    d.Version,
		APIBase:    d.APIBase,
		APIToken:   d.APIToken,
		PickDir:    d.PickDir,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  64 * 1024,
			WriteBufferSize: 64 * 1024,
			// 只监听 127.0.0.1；终端连接本身还要一次性令牌，那比来源校验更硬，
			// 所以这里只拦 Host 明显不对的（防 DNS rebinding），不再挑 Origin
			// —— 挑 Origin 容易把桌面形态自己挡掉。
			CheckOrigin: func(r *http.Request) bool {
				return isLocalHost(r.Host)
			},
		},
	}
}

// Handler 返回路由（已包 CORS）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/targets", s.handleTargets)
	mux.HandleFunc("/api/targets/", s.handleTargetByID)
	mux.HandleFunc("/api/hostkeys", s.handleHostKeys)
	mux.HandleFunc("/api/hostkeys/forget", s.handleHostKeys)
	mux.HandleFunc("/api/recent", s.handleRecent)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/sessions", s.handleSessions)
	mux.HandleFunc("/api/sessions/", s.handleSessionByID)
	mux.HandleFunc("/api/files/", s.handleFiles)
	mux.HandleFunc("/api/monitor", s.handleMonitor)
	mux.HandleFunc("/api/logs/", s.handleLogs)
	mux.HandleFunc("/api/compliance/", s.handleCompliance)
	mux.HandleFunc("/api/threat/", s.handleThreat)
	mux.HandleFunc("/api/db/", s.handleDatabase)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/system/", s.handleSystem)
	mux.HandleFunc("/api/prune", s.handlePruneNow)
	mux.HandleFunc("/ws/term/", s.handleTerminalWS)
	mux.Handle("/", s.staticHandler())

	return s.withCORS(mux)
}

// canonicalPath 按 ServeMux 的口径把路径折成干净形式。
//
// 为什么必须自己做：ServeMux 的 findHandler 是**先 cleanPath 再匹配**的，
// 遇到不干净的路径（`//api/targets`、`/api//targets`）它会直接回一个 307
// 重定向 —— 而那个重定向发生在令牌中间件判断"这不是 /api/ 前缀"之后，
// 于是本机任意进程/页面不带令牌就能靠 `//api/targets` → 307 与
// `/api//targets` → 403 的差别免费探测端点路径。提前规范化，鉴权看到的
// 就是真实路径，两种写法一律 403。
//
// 结尾的 "/" 必须保留：`/api/targets/` 是前缀路由（按 id 操作），
// 折成 `/api/targets` 会变成另一个接口。
func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	cleaned := path.Clean(p)
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}

// withCORS 只放行本机来源，并兜住处理过程中的 panic。
//
// 为什么收紧成"只服务本机"：之前是无条件 Allow-Origin: *，任何网页都能扫本机高位端口
// 找到这个服务，然后读 /api/targets（含主机名与用户名）、触发日志扫描，
// 甚至往已连主机写文件 —— 随机端口不该是唯一门槛。
func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 兜 panic：http.Server 自己不会 recover，一处切片越界就会把整个桌面进程
		// 连同所有活跃终端会话一起带走（采集解析就踩到过）。
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("处理 %s %s 时 panic: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()

		origin := r.Header.Get("Origin")

		// 路径先规范化再谈鉴权（见 canonicalPath）：不这样做的话，
		// ServeMux 会在令牌校验**之后**把 `//api/...` 307 掉，
		// 重定向响应本身就是一次"端点存在性"泄漏。
		if esc := r.URL.EscapedPath(); canonicalPath(esc) != esc {
			norm := canonicalPath(esc)
			decoded, derr := url.PathUnescape(norm)
			if derr != nil {
				http.Error(w, "bad request path", http.StatusBadRequest)
				return
			}
			r.URL.Path = decoded
			r.URL.RawPath = ""
		}

		// 预检请求先放行：它不携带任何实际操作，但如果这里把它挡掉，
		// 浏览器连"能不能带自定义令牌头"都问不出来，请求根本发不出去。
		if r.Method == http.MethodOptions {
			// 只对控制面回显。静态资源不需要 CORS，对它们回显等于
			// 告诉本机任意 localhost 页面"你可以带 X-Awd-Token 来问"。
			if origin != "" && strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Awd-Token")
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 校验顺序：先看令牌。前端页面从 /runtime.js 拿到令牌后每个请求都带上，
		// 带对了就直接放行 —— 不必再猜桌面 WebView 的 Origin 到底是什么。
		//
		// 控制面（/api/）**一律**要求令牌，不再按"非 GET 就算写"去推断。
		// 那个推断在本项目里不成立：
		//   1. Go 的 GET 请求也能带 body，历史上 database.go / files.go 的
		//      写 action 就没校验方法 —— 于是 GET 能在目标库跑 SQL、能删远端文件；
		//   2. Host/Origin 兜底对"本机 + 无 Origin"一律放行（isLocalHost("") 与
		//      isAllowedOrigin("") 都返回 true），本机非浏览器进程连 Host 都不用带。
		// 所以令牌是唯一的硬边界，它必须覆盖所有 /api/ 请求。
		tokenOK := s.APIToken != "" && r.Header.Get("X-Awd-Token") == s.APIToken

		// 静态资源与 /runtime.js 留在令牌之外：页面要先加载它们才能拿到令牌，
		// 一并要求就成了死锁（要令牌才能取到令牌）。
		isControlPlane := strings.HasPrefix(r.URL.Path, "/api/")
		if isControlPlane {
			if !tokenOK {
				log.Printf("拒绝控制面请求 %s %s（缺少或错误的令牌）", r.Method, r.URL.Path)
				http.Error(w, "forbidden: missing token", http.StatusForbidden)
				return
			}
		} else if !tokenOK && (!isLocalHost(r.Host) || !isAllowedOrigin(origin)) {
			msg := "forbidden"
			if !isLocalHost(r.Host) {
				msg = "forbidden: host " + r.Host
			} else {
				msg = "forbidden: origin " + origin
			}
			log.Printf("拒绝请求 %s %s（%s）", r.Method, r.URL.Path, msg)
			// 先补 CORS 头再拒绝：桌面形态是跨源请求，
			// 少了它浏览器只会给出不透明的 "Failed to fetch"，读不到 403 正文
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			http.Error(w, msg, http.StatusForbidden)
			return
		}

		// 只对控制面回显 CORS：-web 下页面与本服务同源、本来不需要 CORS，
		// 而对静态资源（尤其 /runtime.js 里的控制面令牌）回显，等于把令牌
		// 交给本机任意 localhost 来源的页面。桌面形态的跨源请求全是 /api/*。
		// 三个头一起进条件：只回 ACAO 却无条件回 Allow-Headers 口径不一致，
		// 后来人容易误读。
		if isControlPlane || strings.HasPrefix(r.URL.Path, "/ws/") {
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Awd-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
		}
		next.ServeHTTP(w, r)
	})
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errBadJSONBody 是请求体不是合法 JSON 时对外的统一说法。
// 解码器的原文（"invalid character 'x' looking for beginning of value"）
// 对用户没有意义，原文进日志、对外只说这一句。
var errBadJSONBody = errText("请求体 JSON 格式不正确")

// localPathRe 匹配本机 Windows 绝对路径（盘符 + 斜杠）与 UNC 路径。
//
// 老写法是 `[A-Za-z]:\\[^\s"'<>|]*`，两个洞：
//   - `C:\Program Files\x\y.db` 遇到空格就停，"Files\x\y.db" 原样漏给用户；
//   - `C:/Users/x/y.db` 是正斜杠，正则只认反斜杠，整个路径一点都不遮。
//
// 为什么敢吃到行尾：远端目标是 Linux，路径都是 POSIX 形式，
// 用户需要看的远端路径（`/var/www/x: permission denied`）不会被这条匹配到。
// 注意：遮到空白为止，路径后面那句原因（`: access is denied`）会保留下来 ——
// `\b` 保证盘符前不是字母（`http` 里 `p` 前面是 `t`），URL 因此不受影响。
// 一路吃到行尾，保证带空格的路径（`C:\Program Files\...`）也遮全 ——
// 代价是路径后面那句原因也会被盖掉，原文在日志里（见 writeErr 的 log.Printf）。
// 但**不能**把 `http://` 里的 `p:/` 当盘符 —— 那会把
// `连接 http://127.0.0.1:8080/... 失败` 切成 `连接 htt<本地路径>`。
var localPathRe = regexp.MustCompile(`\b[A-Za-z]:[\\/][^\r\n]*|\\\\[^\r\n]*`)

// writeErr 把错误写回前端。
//
// 为什么不原样回 err.Error()：那是 Go 解码器的原文、本机绝对路径、
// 或带库路径的 SQLite 报错 —— 用户看不懂，还顺手把本机目录结构交了出去。
// 所以：这里只回一句能懂的话，原始细节写日志（排查时查得到）。
//
// 例外是本包自己写的 errText（"缺少 target_id"这类），那些文案本来就是
// 写给用户看的，照旧透传；远端路径类报错也保留 —— 用户要靠它定位问题。
func writeErr(w http.ResponseWriter, status int, err error) {
	log.Printf("控制面返回 %d：%v", status, err)
	writeJSON(w, status, map[string]string{"error": userFacingErr(status, err)})
}

func userFacingErr(status int, err error) string {
	if err == nil {
		return "未知错误"
	}
	var et errText
	if errors.As(err, &et) {
		return et.Error()
	}
	// 500 基本都是本机侧故障（库损坏、磁盘、被打断的写），
	// 细节对用户没用，一律只说一句、原文留给日志。
	if status == http.StatusInternalServerError {
		return "服务内部错误（详情见程序日志）"
	}
	if msg := strings.TrimSpace(localPathRe.ReplaceAllString(err.Error(), "<本地路径>")); msg != "" {
		return msg
	}
	if t := http.StatusText(status); t != "" {
		return t
	}
	return "请求失败"
}

// maxBodyBytes 是控制面请求体的上限。
//
// 控制面都是本地小 JSON（SQL、路径、表单），给 8MB 足够宽松。
// 不设上限的话，一个几 MB 的 SQL 就能让只读判定里的字符串处理跑很久
// （修饰语剥离是逐 token 的），把界面卡住。
const maxBodyBytes = 8 << 20

// maxExportBytes 是导出类接口（把前端生成的内容落盘）的上限。
//
// 这不是"限制用户导出多少"，而是别让一个请求把进程打死：
// 导出内容是前端在内存里拼好的，后端再解一份等于翻倍占用
// （实测 64MB 的合法导出会带来 ~270MB 堆分配，按比例 512MB 就是 GB 级）。
const maxExportBytes = 128 << 20

func decode(r *http.Request, v any) error {
	return decodeLimit(r, v, maxBodyBytes)
}

// decodeLimit 带体积上限地解析请求体。
//
// 用 LimitReader 而不是 MaxBytesReader：后者需要 ResponseWriter，
// 而这里的调用点都没有传 w。
// 超限时不能只让 JSON 解析失败 —— 那样前端拿到的是 "unexpected EOF"，
// 用户根本不知道是内容太大；所以读满上限就给出明确原因。
func decodeLimit(r *http.Request, v any, limit int64) error {
	defer r.Body.Close()
	lr := &io.LimitedReader{R: r.Body, N: limit + 1}
	dec := json.NewDecoder(lr)
	err := dec.Decode(v)

	// 先看有没有读满：读满就是超过上限，这时 Decode 报什么都是体积问题
	//（被截断的 JSON 会报 unexpected EOF，不能当成语法错）。
	// 上限向上取整到 MB，免得 <1MB 的上限打出"超过 0 MB"。
	if lr.N <= 0 {
		return fmt.Errorf("请求内容超过 %d MB", (limit+(1<<20)-1)>>20)
	}
	// 没超限时如实报语法错
	if err != nil {
		// 空 body 原样返回 io.EOF：有几个接口**允许空 body**
		//（compliance/delete、compliance/clear、history 清空），
		// 调用方靠 errors.Is(err, io.EOF) 区分"没传"与"传坏了"。
		if errors.Is(err, io.EOF) {
			return err
		}
		// 其余语法错换成一句人话，原文进日志（见 writeErr 的说明）
		log.Printf("请求体 JSON 解析失败: %v", err)
		return errBadJSONBody
	}
	// Decode 只读第一个 JSON 值，后面拖着的东西没人管 —— 一并拒掉
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("请求体里有多余内容")
	}
	return nil
}

// ---------- 处理器 ----------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// 只读接口：非 GET 一律 405（与 database/threat/compliance 同一口径）。
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"name":     "awdshell",
		"version":  s.Version,
		"api_base": s.APIBase,
	})
}

func (s *Server) handleTargets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.Targets.List()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, list)
	case http.MethodPost:
		var in service.SaveTargetInput
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		t, err := s.Targets.Save(in)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, t)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTargetByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/targets/")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if err := s.Targets.Delete(id); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case http.MethodPost: // 测试连接（只做认证探测）
		if err := s.Sessions.TestConnection(id); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "认证成功"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRecent(w http.ResponseWriter, r *http.Request) {
	// 只读接口：非 GET 一律 405（与 database/threat/compliance 同一口径）。
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	list, err := s.Targets.Recent(12)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	// 清空连接历史：这张表以前只增不减，用户没有任何办法清掉自己的连接流水。
	//
	// 毁伤性动作必须限 POST/DELETE —— 令牌是按"非 GET"强制加的，
	// 允许 GET 触发就等于绕过令牌（GET 只走 Host+Origin 兜底，本机来源是被放行的）。
	// 同时"漏传 target_id"不能等于"清空整张表"，那是个反的安全默认。
	if r.URL.Query().Get("action") != "" && r.Method == http.MethodGet {
		// 用 query 参数表达"清空"这个语义本身就不安全（GET 也能带），
		// 带了就直接拒，免得看着像能用
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Method == http.MethodPost || r.Method == http.MethodDelete {
		var in struct {
			TargetID string `json:"target_id"`
			All      bool   `json:"all"`
		}
		// 允许空 body；格式错的 JSON 要如实报，不能静默当"没给参数"。
		// 走 decodeLimit 而不是裸 Decode：以前这里没有体积上限，
		// 一个 9MB 的 body 会被整个读进内存（实测）。
		if err := decodeLimit(r, &in, maxBodyBytes); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		// 不从 query 取 target_id：query 表达写语义本身就该避免
		target := in.TargetID
		if target == "" && !in.All {
			writeErr(w, http.StatusBadRequest, errText("缺少 target_id（要清空全部请显式传 all=true）"))
			return
		}
		if in.All {
			target = ""
		}
		n, err := s.Targets.ClearHistory(target)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": n})
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	list, err := s.Targets.History(200)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.Sessions.List())
	case http.MethodPost:
		var in struct {
			TargetID string `json:"target_id"`
			Cols     int    `json:"cols"`
			Rows     int    `json:"rows"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		h, err := s.Sessions.Open(in.TargetID, in.Cols, in.Rows)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, h)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSessionByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	id := strings.TrimSuffix(rest, "/attach")

	// 断线重连：为还活着的会话换一个新的一次性令牌
	if strings.HasSuffix(rest, "/attach") {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h, err := s.Sessions.Attach(id)
		if err != nil {
			writeErr(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, h)
		return
	}

	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Method != http.MethodDelete {
		// 方法不对回 405：以前和"缺少 id"混在一起回 400，客户端不好区分
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.Sessions.Close(id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleTerminalWS 是终端数据面：远端输出走二进制帧，键盘输入走 JSON 文本帧。
func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/ws/term/")
	// "会话不存在"与"令牌不对"必须回同一个 403。
	//
	// 以前是分开的（不存在 → 404、令牌错 → 403），而 /ws/ 路径**不要求**
	// 控制面令牌（终端另有一次性令牌），于是任何人都能拿它当存在性 oracle：
	// 404 就是"这个会话 id 存在过"。统一回 403，不泄漏会话是否存在。
	sess, ok := s.Sessions.Get(id)
	if !ok || !s.Sessions.ConsumeToken(id, r.URL.Query().Get("token")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// 升级失败要把宽限计时器补回来：否则这个会话既没人在读 pty、
		// 也没有任何计时器会关它，会一直挂到程序退出
		sess.ReleaseWS(30 * time.Second)
		return
	}
	// 有新的 WebSocket 接管，取消断线宽限（页面刷新、短暂断网后重连都会走到这）
	sess.AcquireWS()
	defer conn.Close()

	var writeMu sync.Mutex
	writeBinary := func(b []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteMessage(websocket.BinaryMessage, b)
	}
	writeControl := func(v any) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteJSON(v)
	}

	// 远端 → 前端
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := sess.Read(buf)
			if n > 0 {
				if werr := writeBinary(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				writeControl(map[string]any{"type": "exit", "detail": err.Error()})
				return
			}
		}
	}()

	// 前端 → 远端
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.BinaryMessage {
			if err := sess.WriteInput(data); err != nil {
				break
			}
			continue
		}
		var msg struct {
			Type string `json:"type"`
			Data string `json:"data"`
			Cols int    `json:"cols"`
			Rows int    `json:"rows"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "input":
			if err := sess.WriteInput([]byte(msg.Data)); err != nil {
				goto closed
			}
		case "resize":
			_ = sess.Resize(msg.Cols, msg.Rows)
		case "ping":
			writeControl(map[string]any{"type": "pong"})
		}
	}

closed:
	// 不在这里直接关会话：用户可能只是刷新页面或网络瞬断。
	// 交给宽限期，期间有新的 WebSocket 接管就继续用，一直没人来才真正关闭 ——
	// 读协程也不会永久滞留在 sess.Read 上。
	sess.ReleaseWS(30 * time.Second)
}

// staticAssetExts 是"文件不存在时必须 404、绝不能回退成 index.html"的扩展名。
//
// 回退成 index.html 会以 200 交回一段 HTML：浏览器把 HTML 当 JS/CSS 执行，
// 脚本的 onload 照样触发、只是内容不是代码 —— 表现成"加载成功但功能没生效"，
// 不报错。CodeMirror/xterm 的动态加载就踩过这个坑（模式"下载成功"却没注册）。
var staticAssetExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".css": true, ".map": true,
	".json": true, ".wasm": true, ".txt": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".ico": true, ".webp": true, ".avif": true, ".mp4": true, ".webm": true,
}

// staticHandler 在桌面形态下不提供静态资源（Wails 负责）；浏览器模式下提供并支持 SPA 回退。
func (s *Server) staticHandler() http.Handler {
	if s.Assets == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}
	fileServer := http.FileServer(http.FS(s.Assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 浏览器模式也要能拿到运行时配置：桌面形态由 Wails 的 AssetServer 中间件注入，
		// 而 -web 走的是这里，缺了它前端会请求到 404，并把返回的 index.html 当 JS 解析。
		//
		// 注意这不是"只有自己人拿得到令牌"：取消 CORS 回显挡不住
		// `<script src="http://127.0.0.1:<port>/runtime.js">`（脚本引用不受 CORS 限制），
		// 本机任意来源的页面都能读到令牌。随机端口仍是主要门槛，
		// 真正制约的是控制面只监听 127.0.0.1、且不对外暴露任何凭据。
		if r.URL.Path == "/runtime.js" {
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = fmt.Fprintf(w, "window.__AWDSHELL__ = {apiBase: %q, version: %q, token: %q};\n",
				s.APIBase, s.Version, s.APIToken)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.Assets, p); err != nil {
			// 静态扩展名缺失时就该 404：SPA 回退只服务"前端路由"，
			// 不能把缺的 .js/.css 回成 index.html 200（见 staticAssetExts）。
			//
			// 先去掉结尾斜杠再取扩展名：`path.Ext("foo.js/")` 是空串
			// （最后一个斜杠之后没有点了），`/foo.js/` 会因此落进 SPA 回退、
			// 拿到 200 + HTML —— 正是这条判据要堵的那类。
			if staticAssetExts[strings.ToLower(path.Ext(strings.TrimSuffix(p, "/")))] {
				http.NotFound(w, r)
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

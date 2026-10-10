// Package httpapi 提供本地控制面（HTTP JSON）与数据面（WebSocket），以及文件管理与设置接口。
//
// 在本项目的桌面形态里，静态资源由 Wails 的 AssetServer 提供，本服务只处理 /api/* 与 /ws/*，
// 监听 127.0.0.1 的随机端口；Wails WebView 属于跨源来源，因此统一加 CORS 头。
package httpapi

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
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
	Store      *store.Store
	Assets     fs.FS // 桌面形态下为 nil（静态资源交给 Wails）
	Version    string
	APIBase    string
	APIToken   string // 控制面令牌，注入给页面；带对令牌的请求直接放行
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
	Store      *store.Store
	Assets     fs.FS
	Version    string
	APIBase    string
	APIToken   string

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
		Store:      d.Store,
		Assets:     d.Assets,
		Version:    d.Version,
		APIBase:    d.APIBase,
		APIToken:   d.APIToken,
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
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/prune", s.handlePruneNow)
	mux.HandleFunc("/ws/term/", s.handleTerminalWS)
	mux.Handle("/", s.staticHandler())

	return s.withCORS(mux)
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

		// 预检请求先放行：它不携带任何实际操作，但如果这里把它挡掉，
		// 浏览器连"能不能带自定义令牌头"都问不出来，请求根本发不出去。
		if r.Method == http.MethodOptions {
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Awd-Token")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		// 校验顺序：先看令牌。前端页面从 /runtime.js 拿到令牌后每个请求都带上，
		// 带对了就直接放行 —— 不必再猜桌面 WebView 的 Origin 到底是什么。
		// 没有令牌的（老页面、外部来源）才退回 Host + Origin 校验。
		tokenOK := s.APIToken != "" && r.Header.Get("X-Awd-Token") == s.APIToken
		if !tokenOK && (!isLocalHost(r.Host) || !isAllowedOrigin(origin)) {
			msg := "forbidden"
			if !isLocalHost(r.Host) {
				msg = "forbidden: host " + r.Host
			} else {
				msg = "forbidden: origin " + origin
			}
			log.Printf("拒绝请求 %s %s（%s）", r.Method, r.URL.Path, msg)
			http.Error(w, msg, http.StatusForbidden)
			return
		}

		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Awd-Token")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS")
		next.ServeHTTP(w, r)
	})
}

// ---------- 工具 ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func decode(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// ---------- 处理器 ----------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
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
	list, err := s.Targets.Recent(12)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
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

	if id == "" || r.Method != http.MethodDelete {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.Sessions.Close(id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleTerminalWS 是终端数据面：远端输出走二进制帧，键盘输入走 JSON 文本帧。
func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/ws/term/")
	sess, ok := s.Sessions.Get(id)
	if !ok {
		http.Error(w, "会话不存在", http.StatusNotFound)
		return
	}
	if !s.Sessions.ConsumeToken(id, r.URL.Query().Get("token")) {
		http.Error(w, "令牌无效或已被使用", http.StatusForbidden)
		return
	}
	// 有新的 WebSocket 接管，取消断线宽限（页面刷新、短暂断网后重连都会走到这）
	sess.AcquireWS()

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
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
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
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
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

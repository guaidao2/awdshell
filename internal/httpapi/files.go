package httpapi

import (
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/guaidao2/awdshell/internal/service"
)

// countingReader 统计从请求体实际读到的字节数。
// 用来识别"客户端中途断开"——那种情况下 multipart 不会报错。
type countingReader struct {
	r io.ReadCloser
	n int64
}

// maxRemoteDirLen 是上传时 dir 字段的长度上限（4KB 远超任何真实远端路径）。
const maxRemoteDirLen = 4096

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Close() error { return c.r.Close() }

// safeRemoteJoin 拼出远端目标路径，拒绝能逃出预期目录的写法。
//
// **先拒 dir 里的 `..`**：以前是先 `path.Clean("/"+dir)` 再用折出来的 base 做前缀
// 校验 —— 那等于把 dir 里的 `..` 折掉之后再拿它自己校验自己：`dir=/tmp/..`
// 折成 `/` 之后，任何绝对路径都满足前缀。实测
// `safeRemoteJoin("/tmp/..", "../../etc/passwd")` 会返回 `/etc/passwd`，
// 拿到令牌就能按 SSH 账号权限写 `/etc/cron.d`、`authorized_keys`。
//
// 前端传的是**文件面板当前目录**，正常情况下不含 `..`，所以直接拒绝不损失功能；
// 文件名同样必须是纯文件名（multipart 的 FileName 已过 filepath.Base，
// 但直接调 API 时不一定）。
//
// 注意：`action=write`（内置编辑器保存）是**有意不做这层限制**的 ——
// 运维就是要能改任意路径的配置；这里挡的是"上传时目录被构造"这一条路。
func safeRemoteJoin(dir, name string) (string, error) {
	if strings.Contains(dir, "..") {
		return "", fmt.Errorf("远端目录不允许包含 ..: %s", dir)
	}
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("远端文件名不合法: %s", name)
	}
	base := path.Clean("/" + strings.TrimSpace(dir))
	dest := path.Clean(path.Join(base, name))
	// base 是根目录时不能拼 base+"/"（那是 "//"，任何 dest 都不满足前缀），
	// 否则用户在文件面板切到 `/` 之后，上传会报一句误导人的"跑到目标目录之外"。
	if base != "/" && dest != base && !strings.HasPrefix(dest, base+"/") {
		return "", fmt.Errorf("远端路径不能跑到目标目录之外: %s", name)
	}
	if dest == base || dest == "/" {
		return "", fmt.Errorf("远端路径不合法: %s", name)
	}
	return dest, nil
}

// fileRoutes 处理 /api/files/ 下的所有文件操作。
func (s *Server) handleFiles(w http.ResponseWriter, r *http.Request) {
	action := strings.TrimPrefix(r.URL.Path, "/api/files/")
	q := r.URL.Query()
	targetID := q.Get("target_id")

	// 只读 action 明确只允许 GET，写 action 明确只允许 POST。
	// 之前这个 switch 一处方法校验都没有，而 Go 的 GET 也能带 body ——
	// 裸 GET /api/files/delete?target_id=x 就能删掉远端主机上的文件
	//（trash:false 还是永久删除）。
	switch action {
	case "list", "home", "startdir", "cwd", "read", "download":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	default:
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	}

	switch action {
	case "list":
		if targetID == "" {
			writeErr(w, http.StatusBadRequest, errText("缺少 target_id"))
			return
		}
		list, err := s.Files.List(targetID, q.Get("path"))
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, list)

	case "home":
		home, err := s.Files.Home(targetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"home": home})

	case "startdir":
		// 有效起始目录：配置的目录不存在时回退到家目录（回退信息一并返回给 UI）。
		info, err := s.Files.ResolveStartDir(targetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, info)

	case "cwd":
		// 探测交互终端当前所在目录（文件面板的"同步终端目录"）。
		p, err := s.Files.TermCwd(targetID)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"path": p})

	case "read":
		content, err := s.Files.ReadText(targetID, q.Get("path"), service.TextMaxBytes)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"content": content})

	case "write":
		var in struct {
			TargetID string `json:"target_id"`
			Path     string `json:"path"`
			Content  string `json:"content"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Files.WriteText(in.TargetID, in.Path, in.Content); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "bytes": len(in.Content)})

	case "mkdir":
		var in struct {
			TargetID string `json:"target_id"`
			Path     string `json:"path"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Files.Mkdir(in.TargetID, in.Path); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case "chmod":
		var in struct {
			TargetID string `json:"target_id"`
			Path     string `json:"path"`
			Mode     string `json:"mode"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Files.Chmod(in.TargetID, in.Path, in.Mode); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": in.Mode})

	case "rename":
		var in struct {
			TargetID string `json:"target_id"`
			Old      string `json:"old"`
			New      string `json:"new"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if err := s.Files.Rename(in.TargetID, in.Old, in.New); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})

	case "delete":
		var in struct {
			TargetID string   `json:"target_id"`
			Paths    []string `json:"paths"`
			Trash    *bool    `json:"trash"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		trash := true // 默认移入回收站，符合"误删代价高"的设计
		if in.Trash != nil {
			trash = *in.Trash
		}
		// 逐条报告结果：部分成功时也要如实告诉调用方哪些删了、哪些没删
		res, err := s.Files.Delete(in.TargetID, in.Paths, trash)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		// **有失败项就不能回 200**：唯一调用方只 `await req(...)`、不看 body，
		// 200 会让状态栏显示"已删除"，而刷新后文件还在（删没权限的文件、
		// 删已被别人删掉的路径都会这样）。409 = 请求合法但部分没做成。
		status := http.StatusOK
		if len(res.Failed) > 0 {
			status = http.StatusConflict
		}
		writeJSON(w, status, map[string]any{
			"ok":      len(res.Failed) == 0,
			"trashed": trash,
			"deleted": res.Deleted,
			"failed":  res.Failed,
		})

	case "save-to-dir":
		var in struct {
			TargetID string `json:"target_id"`
			Path     string `json:"path"`
		}
		if err := decode(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		if in.TargetID == "" {
			in.TargetID = targetID
		}
		if in.TargetID == "" {
			writeErr(w, http.StatusBadRequest, errText("缺少 target_id"))
			return
		}
		if in.Path == "" {
			writeErr(w, http.StatusBadRequest, errText("没有指定要下载的路径"))
			return
		}
		// 目录**只**从设置取，不接受请求体指定（同 system.go 的说明）
		dir := ""
		if s.Settings != nil {
			dir = s.Settings.Get().DownloadDir
		}
		local, err := s.Files.DownloadToDir(in.TargetID, in.Path, dir)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "saved_to": local})

	case "download":
		remotePath := q.Get("path")
		// 先确认读得到、而且是文件，再发响应头 —— 头一旦发出就没法回错误了
		if err := s.Files.EnsureReadableFile(targetID, remotePath); err != nil {
			writeErr(w, http.StatusBadGateway, err)
			return
		}
		name := path.Base(remotePath)
		w.Header().Set("Content-Type", "application/octet-stream")
		// 用 FormatMediaType 组装，并先滤掉控制字符：
		// 直接把文件名拼进头里，遇到 %0a 这种会让 net/http 在校验头值时 panic，
		// 而且这个 panic 发生在响应写出路径上，handler 里的 recover 也救不回。
		w.Header().Set("Content-Disposition",
			mime.FormatMediaType("attachment", map[string]string{"filename": safeFilename(name)}))
		if err := s.Files.Download(targetID, remotePath, w); err != nil {
			log.Printf("下载 %s 失败（响应已开始，无法回错误）: %v", remotePath, err)
			return
		}

	case "upload":
		// 不设总量上限：运维要传的东西可能很大（ISO、数据库备份、日志归档），
		// 谁也不知道用户这次要传多少，加一道墙只会挡住正当用法。
		//
		// 也不用 ParseMultipartForm：它会把超过 32MB 的部分落到**系统临时目录**，
		// 传一个 5GB 的备份就要占 5GB 系统盘，C 盘小的话直接失败。
		// 这里用 MultipartReader 边读边传，全程不经过本地磁盘。
		// 依赖前端把 target_id / dir 放在 file 之前（见 files.js 的 append 顺序）。
		// 包一层计数器：客户端中途断开时 multipart 的 part 会"正常"读到 EOF
		// 而不报错，只有比对实际收到的字节数与声明长度才知道请求被截断了。
		cr := &countingReader{r: r.Body}
		r.Body = cr

		mr, err := r.MultipartReader()
		if err != nil {
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		var tid, dir string
		var dirSeen bool
		var stageTmp, stageDest string
		var stageN int64
		done := false
		abort := func() {
			if stageTmp != "" {
				// 清理失败不能吞：临时文件会留在远端（.awdshell-part-*），
				// 用户在文件面板看到它却不知道哪来的，也查不到是谁的锅。
				if err := s.Files.AbortUpload(tid, stageTmp); err != nil {
					log.Printf("清理远端临时文件 %s（目标 %s）失败: %v", stageTmp, tid, err)
				}
				stageTmp = ""
			}
		}
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				abort()
				writeErr(w, http.StatusBadRequest, err)
				return
			}
			switch part.FormName() {
			case "target_id":
				// **只在还没拿到时接受**：file 已经 Stage 之后再出现一个 target_id
				//（哪怕是空的）会把 tid 覆盖掉，于是 CommitUpload 用空 target 失败，
				// 而 abort 里的 AbortUpload("") 又因为 Auth("") 失败删不掉临时文件
				// —— 远端就留下一个 .awdshell-part-* 且接口只回 502。
				if tid == "" {
					b, _ := io.ReadAll(io.LimitReader(part, 4096))
					tid = strings.TrimSpace(string(b))
				}
			case "dir":
				// 只认第一个 dir：重复字段里"最后一个生效"意味着谁后发谁说了算，
				// 而它决定文件落在远端哪个目录（跟 target_id 同一个道理）。
				// 另外给个长度上限 —— 它会被拼进远端路径，超长路径既没意义，
				// 还会让 safeRemoteJoin / SFTP 报出难懂的错。
				if !dirSeen {
					// **迟到的 dir 必须拒，不能静默丢掉**：file 已经按"空 dir"
					// （也就是远端根目录）暂存完了，此刻才说目录，文件已经在
					// /x 而不是 /tmp/x —— 接口以前照样回 200 说上传成功，
					// 用户以为传到了目录里。target_id 迟到会报"字段顺序不对"，
					// dir 同样处理（前端本来就把 dir 排在 file 前面）。
					//
					// 为什么不改成"读完所有 part 再算 safeRemoteJoin"：
					// 暂存用的临时文件名与 Mkdir 都建在目标目录下
					//（StageUpload 用 path.Dir(remotePath)），想推迟得让 service 层
					// 支持"先暂存到别处、落地时再改名"，那是更大的改动。
					if done {
						abort()
						writeErr(w, http.StatusBadRequest,
							errText("上传字段顺序不对：dir 必须在 file 之前"))
						return
					}
					dirSeen = true
					b, _ := io.ReadAll(io.LimitReader(part, maxRemoteDirLen+1))
					if len(b) > maxRemoteDirLen {
						// 兜住"已经暂存过东西"的边角（文件 part 没有文件名、
						// 被跳过时 done 仍是 false），退出前清理，别在远端留下
						// .awdshell-part-*
						abort()
						writeErr(w, http.StatusBadRequest,
							fmt.Errorf("dir 字段过长（上限 %d 字节）", maxRemoteDirLen))
						return
					}
					dir = strings.TrimSpace(string(b))
				}
			case "file":
				name := part.FileName()
				if name == "" {
					continue
				}
				if done {
					// 一次请求只传一个文件（前端是逐个发的）。
					// 多余的 file part 不能静默丢掉。
					abort()
					writeErr(w, http.StatusBadRequest, errText("一次请求只能上传一个文件"))
					return
				}
				if tid == "" {
					// 此刻还分不清两种原因：target_id 可能只是排在 file 后面
					//（顺序问题），也可能**压根没传**。以前一律说"字段顺序不对"，
					// 完全没传的用户照着提示去调顺序，怎么调都不对。
					// 所以把剩下的 part 读完再判断（只认不落地，不写任何东西）。
					lateTarget := false
					for {
						rest, rerr := mr.NextPart()
						if rerr != nil {
							break
						}
						if rest.FormName() == "target_id" {
							b, _ := io.ReadAll(io.LimitReader(rest, 4096))
							if strings.TrimSpace(string(b)) != "" {
								lateTarget = true
							}
						}
					}
					if lateTarget {
						writeErr(w, http.StatusBadRequest,
							errText("上传字段顺序不对：target_id 必须在 file 之前"))
					} else {
						writeErr(w, http.StatusBadRequest, errText("上传缺少 target_id"))
					}
					return
				}
				dest, err := safeRemoteJoin(dir, name)
				if err != nil {
					writeErr(w, http.StatusBadRequest, err)
					return
				}
				// 只暂存、不落地：等确认整个请求体都收全了再改名。
				// stage 正常就是 s.Files.StageUpload（见 Server.stageUpload 的说明）。
				stage := s.Files.StageUpload
				if s.stageUpload != nil {
					stage = s.stageUpload
				}
				tmp, n, err := stage(tid, dest, part)
				if err != nil {
					writeErr(w, http.StatusBadGateway, err)
					return
				}
				stageTmp, stageDest, stageN = tmp, dest, n
				done = true
				// 刻意不 break：继续读到真的 EOF，才能知道请求体是完整的。
				// 客户端中途断开时 multipart 的 part 会"正常"结束，光看 part 读没读错
				// 是发现不了的。
			}
		}
		if !done {
			writeErr(w, http.StatusBadRequest, errText("请求里没有文件"))
			return
		}
		// 双保险：收到真 EOF 了，再对一次实际字节数与声明长度。
		//
		// 这条只是**兜底**，不是主防线 —— 审计实测所有截断都由 multipart 自己
		// 先报 `multipart: NextPart: EOF`（走上面那条分支），这里够不到；
		// 它真正能拦的是"Content-Length 被虚报"。容差给 8KB：
		// 正常请求实测 delta 恒为 0，而带 8KB 收尾注释（epilogue）的请求
		// delta 约 4.7KB —— 容差太小会把这种**完整**上传误判成中断。
		// chunked 没有 Content-Length（-1），跳过。
		const slack = 8 << 10
		if r.ContentLength > 0 && cr.n < r.ContentLength-slack {
			abort()
			writeErr(w, http.StatusBadRequest,
				fmt.Errorf("上传中断：只收到 %d / %d 字节", cr.n, r.ContentLength))
			return
		}
		// 到这里才落地：请求体完整，原文件在被替换前始终没动过
		if err := s.Files.CommitUpload(tid, stageTmp, stageDest); err != nil {
			abort()
			// 目标是目录是客户端的路径问题，不是服务端故障
			status := http.StatusBadGateway
			if errors.Is(err, service.ErrTargetIsDir) {
				status = http.StatusBadRequest
			}
			writeErr(w, status, err)
			return
		}
		writeJSON(w, http.StatusOK,
			map[string]any{"ok": true, "path": stageDest, "bytes": stageN, "name": path.Base(stageDest)})

	default:
		http.NotFound(w, r)
	}
}

type errText string

func (e errText) Error() string { return string(e) }

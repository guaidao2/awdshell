package service

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/guaidao2/awdshell/internal/infra/collect"
	"github.com/guaidao2/awdshell/internal/infra/sshx"

	"golang.org/x/crypto/ssh"
)

// sampleInterval 是首次采样时两次取样的间隔。
//
// 为什么要等：CPU 占用与网络速率都是**两次采样的差值**，第一次没有基准，
// 界面上会是一片 0；等 400ms 再采一次，一打开页面就有真实数字。
// 代价是首次采样慢 400ms —— 这个数字是"够采到真实间隔"与"用户感觉不到卡"的折中。
var sampleInterval = 400 * time.Millisecond

// MonitorService 采集目标主机的资源指标（走连接池里的同一条 SSH 连接）。
type MonitorService struct {
	targets *TargetService
	pool    *sshx.Pool

	mu     sync.Mutex
	last   map[string]collect.Snapshot
	lastAt map[string]time.Time

	// sampleLocks 把**同一个目标**的采样串起来（键是 targetID）。
	//
	// 为什么需要：监控面板刷新、切目标、手动点刷新都可能并发调 Sample，
	// 而 CPU/速率全靠 last 与 lastAt 当基准 —— 两次并发采样会各自覆盖同一份
	// 基准，算出来的百分比没有意义（差值区间与时间区间对不上）。
	// 用 TryLock 而不是 Lock：并发时后到的那次直接返回 ErrSampling，
	// 而不是排队再采一遍（排队只会让界面更慢，数字也不会更准）。
	//
	// **为什么是按目标而不是一把全局锁**（审计 M1）：一次采样最长约 27 秒
	//（400ms 首次间隔 + 12s 拨号 + 15s 采集）。全局锁下 A 还在采的时候切到 B，
	// B 拿到的是"上一次采样还没结束"，前端把它显示成红色的"采集失败"并停在
	// A 的数字上 —— 实际 B 什么都没错，只是被 A 挡住了。
	// 不同目标之间本来就没有共享状态（last/lastAt 都是按 targetID 分开的），
	// 没有任何理由互相阻塞。
	sampleLocks map[string]*sync.Mutex
}

// NewMonitorService 构造服务。
func NewMonitorService(targets *TargetService, pool *sshx.Pool) *MonitorService {
	return &MonitorService{
		targets:     targets,
		pool:        pool,
		last:        map[string]collect.Snapshot{},
		lastAt:      map[string]time.Time{},
		sampleLocks: map[string]*sync.Mutex{},
	}
}

// ErrSampling 表示"这个目标上一次采样还没结束"。
//
// 为什么单独给一个错误值：它是**并发拒绝**，不是采集失败。以前它与真实的
// 采集错误共用一条路径，控制面一律回 502，界面画成红色的"采集失败" ——
// 用户在 A、B 之间切一下就看到一句假故障，而 B 其实一点问题都没有。
// 控制面据此回 409（"跳过这一轮"），前端不会把它当成故障。
var ErrSampling = errors.New("这个目标的上一次采样还没结束，请稍候再试")

// lockFor 取某个目标的采样锁（懒建）。s.mu 保护这张表本身。
func (s *MonitorService) lockFor(targetID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	lk := s.sampleLocks[targetID]
	if lk == nil {
		lk = &sync.Mutex{}
		s.sampleLocks[targetID] = lk
	}
	return lk
}

// NetRate 网卡速率（字节/秒）与累计量。
type NetRate struct {
	Name    string  `json:"name"`
	RxBps   float64 `json:"rx_bps"`
	TxBps   float64 `json:"tx_bps"`
	RxTotal uint64  `json:"rx_total"`
	TxTotal uint64  `json:"tx_total"`
}

// CoreUsage 是单个 CPU 核心的占用。
type CoreUsage struct {
	ID      int     `json:"id"`
	Percent float64 `json:"percent"`
}

// NameCount 是"名称 → 次数"的聚合项，用于各种排行。
type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Metric 是一次采样的结果，直接给 UI 用。
type Metric struct {
	TargetID   string      `json:"target_id"`
	TS         int64       `json:"ts"`
	CPUPercent float64     `json:"cpu_percent"`
	CPUCores   []CoreUsage `json:"cpu_cores"`
	// ProcTotal 是进程总数；**-1 表示没采到**（不是 0 个进程）。
	ProcTotal  int                 `json:"proc_total"`
	MemBuffers uint64              `json:"mem_buffers"`
	MemCached  uint64              `json:"mem_cached"`
	OSName     string              `json:"os_name"`
	Kernel     string              `json:"kernel"`
	TimeZone   string              `json:"timezone"`
	Load1      float64             `json:"load1"`
	Load5      float64             `json:"load5"`
	Load15     float64             `json:"load15"`
	UptimeSec  int64               `json:"uptime_sec"`
	MemTotal   uint64              `json:"mem_total"`
	MemUsed    uint64              `json:"mem_used"`
	MemFree    uint64              `json:"mem_free"`
	MemPercent float64             `json:"mem_percent"`
	SwapTotal  uint64              `json:"swap_total"`
	SwapUsed   uint64              `json:"swap_used"`
	Disks      []collect.DiskUsage `json:"disks"`
	Conns      []collect.Conn      `json:"conns"`
	ConnStates []NameCount         `json:"conn_states"`
	ConnRemote []NameCount         `json:"conn_remote"`
	ConnPorts  []NameCount         `json:"conn_ports"`
	Net        []NetRate           `json:"net"`
	Procs      []collect.ProcInfo  `json:"procs"`
	Listeners  []collect.Listener  `json:"listeners"`
	First      bool                `json:"first"` // 首次采样（CPU/速率还没有基准）

	// Collected=false 表示关键段（/proc/stat 的 CPU、/proc/meminfo）没采到。
	// 前端据此把面板标成"未采集到"，而不是画成 CPU 0% / 内存 0% ——
	// 后者看起来像一台正常空闲的机器，那是**错误数据**而不是缺失数据。
	Collected bool     `json:"collected"`
	Missing   []string `json:"missing"`

	// Problems 是"脚本说采到了、但解析端没提出东西"的说明（人话）。
	// 前端拿到非空时应当提示"这一段的数据可能不完整"，而不是把空列表当真。
	Problems []string `json:"problems"`
}

// Sample 采集一次；首次调用会补采一次以便算出 CPU 占用与网络速率。
func (s *MonitorService) Sample(targetID string) (Metric, error) {
	// 只锁这一个目标：别的目标照采（见 sampleLocks 的说明）。
	lk := s.lockFor(targetID)
	if !lk.TryLock() {
		return Metric{}, ErrSampling
	}
	defer lk.Unlock()

	snap, err := s.rawSample(targetID)
	if err != nil {
		return Metric{}, err
	}

	s.mu.Lock()
	prev, hadPrev := s.last[targetID]
	prevAt := s.lastAt[targetID]
	s.last[targetID] = snap
	s.lastAt[targetID] = time.Now()
	s.mu.Unlock()

	// 首次没有基准：等一小会再采一次，这样界面一打开就有真实数字。
	if !hadPrev {
		time.Sleep(sampleInterval)
		second, err2 := s.rawSample(targetID)
		if err2 == nil {
			s.mu.Lock()
			s.last[targetID] = second
			s.lastAt[targetID] = time.Now()
			s.mu.Unlock()
			prev, prevAt, hadPrev = snap, time.Now().Add(-sampleInterval), true
			snap = second
		}
	}

	return buildMetric(targetID, snap, prev, prevAt, hadPrev), nil
}

// Forget 忘掉某个目标的采样基准。
//
// 为什么必须清：s.last 里存的是上一次的 CPU 时间片与网卡累计字节，
// 目标删掉（或它的主机/凭据改成另一台机器）之后这份数据不该继续留着 ——
// 同一个 targetID 会拿一个陈旧基准去算 CPU 与速率，画出来的百分比是假的
// （而且 First=false，界面把它当真实数值画出来，属于**错误数据**而非缺失数据）。
// 接线在 main.go：删目标挂 AddOnDelete、**更新已有目标**挂 AddOnSave
// （审计 H2 漏的就是 Save 这条路：编辑目标换一台机器时 Save 保留原 ID）。
func (s *MonitorService) Forget(targetID string) {
	s.mu.Lock()
	delete(s.last, targetID)
	delete(s.lastAt, targetID)
	delete(s.sampleLocks, targetID)
	s.mu.Unlock()
}

// HasBaselineForTest 报告某个目标是否还留着采样基准。
//
// 为什么导出：audit44 H2 的接线在 main.go，而 main 包测不了 service 的内部字段。
// 这条只读探针让"Save 之后基准清掉了没有"能在包外断言（生产代码不用它）。
func (s *MonitorService) HasBaselineForTest(targetID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.last[targetID]
	return ok
}

// SeedBaselineForTest 塞一份假的采样基准（模拟"已经采过一次"）。
func (s *MonitorService) SeedBaselineForTest(targetID string) {
	s.mu.Lock()
	s.last[targetID] = collect.Snapshot{}
	s.lastAt[targetID] = time.Now()
	s.sampleLocks[targetID] = &sync.Mutex{}
	s.mu.Unlock()
}

// rawSample 执行采集脚本并解析。
func (s *MonitorService) rawSample(targetID string) (collect.Snapshot, error) {
	target, auth, err := s.targets.Auth(targetID)
	if err != nil {
		return collect.Snapshot{}, err
	}
	key := poolKey(targetID)
	conn, err := s.pool.Acquire(key, func() (*ssh.Client, error) {
		return sshx.Dial(target.Host, target.Port, auth, 12*time.Second)
	})
	if err != nil {
		return collect.Snapshot{}, err
	}
	out, err := sshx.RunOutput(conn, collect.Script, 15*time.Second)
	if err != nil {
		// 采集脚本里某条命令失败不算连接坏（脚本自己会 2>/dev/null 兜底），
		// 只有连接类错误才丢弃共享连接，否则会连带掐断终端
		if sshx.IsConnError(err) {
			s.pool.DropIf(key, conn) // 按身份删，别误删别人刚换上的那条
		}
		return collect.Snapshot{}, fmt.Errorf("采集失败: %w", err)
	}
	return collect.Parse(out), nil
}

func buildMetric(targetID string, snap, prev collect.Snapshot, prevAt time.Time, hadPrev bool) Metric {
	now := time.Now()
	m := Metric{
		TargetID:  targetID,
		TS:        now.UnixMilli(),
		Load1:     snap.Load1,
		Load5:     snap.Load5,
		Load15:    snap.Load15,
		UptimeSec: int64(snap.UptimeSec),
		Disks:     snap.Disks,
		Procs:     snap.Procs,
		Listeners: snap.Listeners,
		First:     !hadPrev,
		Collected: snap.Collected,
		Missing:   snap.Missing,
		Problems:  snap.Problems,
	}

	if m.Missing == nil {
		m.Missing = []string{}
	}
	if m.Problems == nil {
		m.Problems = []string{}
	}

	// CPU：两次 /proc/stat 的差值
	if hadPrev {
		dt := float64(snap.CPU.Total()) - float64(prev.CPU.Total())
		di := float64(snap.CPU.IdleAll()) - float64(prev.CPU.IdleAll())
		if dt > 0 {
			m.CPUPercent = clampFloat((1-di/dt)*100, 0, 100)
		}
	}

	// 分核占用：同样用差值算，逐核展示才能看出是不是单核跑满
	for i := range snap.CPUCores {
		item := CoreUsage{ID: i}
		if hadPrev && i < len(prev.CPUCores) {
			dt := float64(snap.CPUCores[i].Total()) - float64(prev.CPUCores[i].Total())
			di := float64(snap.CPUCores[i].IdleAll()) - float64(prev.CPUCores[i].IdleAll())
			if dt > 0 {
				item.Percent = clampFloat((1-di/dt)*100, 0, 100)
			}
		}
		m.CPUCores = append(m.CPUCores, item)
	}
	// 进程总数：**没数出来时给 -1，不给 0**。
	//
	// 0 在这件事上是有意义的数字（"这台机器没有进程"），而 BusyBox 上
	// `ps -e --no-headers` 失败、`wc -l` 照样给 0 —— 界面会把一个假的 0
	// 画成"0 个进程"。用 -1 表达"没采到"，前端据此显示"—"或"未采集到"。
	m.ProcTotal = -1
	if snap.ProcTotalValid {
		m.ProcTotal = snap.ProcTotal
	}
	m.MemBuffers = snap.Mem["Buffers"] * 1024
	m.MemCached = snap.Mem["Cached"] * 1024
	m.OSName = snap.OSName
	m.Kernel = snap.Kernel
	m.TimeZone = snap.TimeZone

	// 连接聚合：状态分布、对端 IP 排行、对端端口排行。
	// 端口排行能直接看出这台机器在往外连什么服务，是排查外联最直观的一列。
	m.Conns = snap.Conns
	stateCount := map[string]int{}
	remoteCount := map[string]int{}
	portCount := map[string]int{}
	for _, c := range snap.Conns {
		if c.State != "" {
			stateCount[c.State]++
		}
		if c.Remote != "" && c.Remote != "0.0.0.0" && c.Remote != "::" && c.Remote != "*" {
			remoteCount[c.Remote]++
		}
		if c.RPort > 0 {
			portCount[strconv.Itoa(c.RPort)]++
		}
	}
	m.ConnStates = topCounts(stateCount, 8)
	m.ConnRemote = topCounts(remoteCount, 10)
	m.ConnPorts = topCounts(portCount, 10)

	// 内存（/proc/meminfo 单位是 KB）
	total := snap.Mem["MemTotal"]
	avail := snap.Mem["MemAvailable"]
	if avail == 0 {
		avail = snap.Mem["MemFree"]
	}
	m.MemTotal = total * 1024
	m.MemFree = avail * 1024
	if total > 0 && total >= avail {
		used := total - avail
		m.MemUsed = used * 1024
		m.MemPercent = float64(used) / float64(total) * 100
	}
	if st := snap.Mem["SwapTotal"]; st > 0 {
		m.SwapTotal = st * 1024
		m.SwapUsed = (st - snap.Mem["SwapFree"]) * 1024
	}

	// 网络速率
	secs := now.Sub(prevAt).Seconds()
	prevByName := map[string]collect.NetIface{}
	for _, p := range prev.Net {
		prevByName[p.Name] = p
	}
	for _, ni := range snap.Net {
		item := NetRate{Name: ni.Name, RxTotal: ni.RxBytes, TxTotal: ni.TxBytes}
		if hadPrev && secs > 0 {
			if p, ok := prevByName[ni.Name]; ok {
				if ni.RxBytes >= p.RxBytes {
					item.RxBps = float64(ni.RxBytes-p.RxBytes) / secs
				}
				if ni.TxBytes >= p.TxBytes {
					item.TxBps = float64(ni.TxBytes-p.TxBytes) / secs
				}
			}
		}
		m.Net = append(m.Net, item)
	}
	if m.Net == nil {
		m.Net = []NetRate{}
	}
	if m.Disks == nil {
		m.Disks = []collect.DiskUsage{}
	}
	if m.Procs == nil {
		m.Procs = []collect.ProcInfo{}
	}
	if m.Listeners == nil {
		m.Listeners = []collect.Listener{}
	}
	if m.CPUCores == nil {
		m.CPUCores = []CoreUsage{}
	}
	if m.Conns == nil {
		m.Conns = []collect.Conn{}
	}
	if m.ConnStates == nil {
		m.ConnStates = []NameCount{}
	}
	if m.ConnRemote == nil {
		m.ConnRemote = []NameCount{}
	}
	if m.ConnPorts == nil {
		m.ConnPorts = []NameCount{}
	}
	return m
}

// topCounts 把计数 map 排成降序的前 n 项。
func topCounts(m map[string]int, n int) []NameCount {
	out := make([]NameCount, 0, len(m))
	for k, v := range m {
		out = append(out, NameCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

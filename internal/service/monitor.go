package service

import (
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/guaidao2/awdshell/internal/infra/collect"
	"github.com/guaidao2/awdshell/internal/infra/sshx"

	"golang.org/x/crypto/ssh"
)

// MonitorService 采集目标主机的资源指标（走连接池里的同一条 SSH 连接）。
type MonitorService struct {
	targets *TargetService
	pool    *sshx.Pool

	mu     sync.Mutex
	last   map[string]collect.Snapshot
	lastAt map[string]time.Time
}

// NewMonitorService 构造服务。
func NewMonitorService(targets *TargetService, pool *sshx.Pool) *MonitorService {
	return &MonitorService{
		targets: targets,
		pool:    pool,
		last:    map[string]collect.Snapshot{},
		lastAt:  map[string]time.Time{},
	}
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
	TargetID   string              `json:"target_id"`
	TS         int64               `json:"ts"`
	CPUPercent float64             `json:"cpu_percent"`
	CPUCores   []CoreUsage         `json:"cpu_cores"`
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
}

// Sample 采集一次；首次调用会补采一次以便算出 CPU 占用与网络速率。
func (s *MonitorService) Sample(targetID string) (Metric, error) {
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
		time.Sleep(400 * time.Millisecond)
		second, err2 := s.rawSample(targetID)
		if err2 == nil {
			s.mu.Lock()
			s.last[targetID] = second
			s.lastAt[targetID] = time.Now()
			s.mu.Unlock()
			prev, prevAt, hadPrev = snap, time.Now().Add(-400*time.Millisecond), true
			snap = second
		}
	}

	return buildMetric(targetID, snap, prev, prevAt, hadPrev), nil
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
		s.pool.Drop(key)
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
	m.ProcTotal = snap.ProcTotal
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

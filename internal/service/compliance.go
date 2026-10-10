package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/guaidao2/awdshell/internal/infra/compliance"
	"github.com/guaidao2/awdshell/internal/infra/sshx"
	"github.com/guaidao2/awdshell/internal/store"

	"golang.org/x/crypto/ssh"
)

// ComplianceService 在目标机上执行安全基线核查。
type ComplianceService struct {
	targets *TargetService
	pool    *sshx.Pool
	store   *store.Store
}

// NewComplianceService 构造服务。
func NewComplianceService(targets *TargetService, pool *sshx.Pool, st *store.Store) *ComplianceService {
	return &ComplianceService{targets: targets, pool: pool, store: st}
}

// Report 是一次核查报告。
type Report struct {
	TargetID  string              `json:"target_id"`
	Target    string              `json:"target"`
	ReportID  int64               `json:"report_id"`
	StartedAt int64               `json:"started_at"`
	ElapsedMs int64               `json:"elapsed_ms"`
	Summary   compliance.Summary  `json:"summary"`
	Results   []compliance.Result `json:"results"`
	Problems  []string            `json:"problems"`
}

// Checks 返回全部检查项，供界面展示与挑选。
func (s *ComplianceService) Checks() ([]compliance.Check, []string, error) {
	sets, problems, err := compliance.LoadSets()
	if err != nil {
		return nil, nil, err
	}
	return compliance.AllChecks(sets), problems, nil
}

// Run 执行核查；onlyIDs 为空表示跑全部检查项。
func (s *ComplianceService) Run(targetID string, onlyIDs []string) (Report, error) {
	return s.RunContext(context.Background(), targetID, onlyIDs)
}

// RunContext 与 Run 相同，但带上 context：一轮 60+ 项动辄几分钟，
// 用户关掉页面或切走时应该能提前收手，而不是白跑完再把结果丢掉。
func (s *ComplianceService) RunContext(ctx context.Context, targetID string, onlyIDs []string) (Report, error) {
	target, auth, err := s.targets.Auth(targetID)
	if err != nil {
		return Report{}, err
	}
	conn, err := s.pool.Acquire(poolKey(targetID), func() (*ssh.Client, error) {
		return sshx.Dial(target.Host, target.Port, auth, 12*time.Second)
	})
	if err != nil {
		return Report{}, err
	}
	// 一轮 60+ 项 × 每项最长 10 秒，很容易跑过 idle（默认 5 分钟）。
	// 不收 Hold 的话 reaper 会在中途把这条连接按空闲回收，余下各项全是
	// "连接已断开" —— 而用户什么都没做错。
	release := s.pool.Hold(conn)
	defer release()

	checks, problems, err := s.Checks()
	if err != nil {
		return Report{}, err
	}

	started := time.Now()
	// 连接中途断掉时不要继续把余下每项都跑满超时：一轮 60+ 项 × 10 秒
	// 会让用户干等十几分钟，而且报告里全是"超时"、看不出真实原因。
	// 一旦遇到连接类错误就标记，余下项直接返回错误（Runner 会记成 error），
	// 并把原因写进 Problems。
	//
	// connBroken 用一把锁保护：exec 会被 Runner 反复调用，而它读写这个标志；
	// 只要有任何一个调用方（或将来某次改动）让检查项并发执行，无保护的读写就是
	// 数据竞争 —— 而"读到旧值"的后果是余下几十项每项都等到超时。
	var brokenMu sync.Mutex
	connBroken := false
	exec := func(cmd string, timeoutSec int) (string, error) {
		brokenMu.Lock()
		broken := connBroken
		brokenMu.Unlock()
		if broken {
			return "", fmt.Errorf("连接已断开，跳过余下检查项")
		}
		if timeoutSec <= 0 {
			timeoutSec = 10
		}
		// 单项命令返回非 0 很正常（比如文件不存在），不能因此丢掉整条连接
		out, err := sshx.RunOutput(conn, cmd, time.Duration(timeoutSec)*time.Second)
		if err != nil && sshx.IsConnError(err) {
			brokenMu.Lock()
			connBroken = true
			brokenMu.Unlock()
			// 共享连接确实坏了：摘掉池里这条，别让后续操作继续踩。
			// **手里这条 conn**：按身份摘，别误删别人刚换上的那条。
			s.pool.DropIf(poolKey(targetID), conn)
		}
		return out, err
	}
	// RunWithContext 的第二个返回值是 problems：里面会带上"onlyIDs 里有未知 ID"
	// 与"取消时还有多少项没跑"，以前用 Run() 全丢了 —— 用户指定了错的检查项 ID
	// 却什么提示都没有。
	results, runProblems := compliance.RunWithContext(ctx, checks, exec, onlyIDs, nil)
	problems = append(problems, runProblems...)
	brokenMu.Lock()
	broken := connBroken
	brokenMu.Unlock()
	if broken {
		problems = append(problems, "执行中途连接断开，余下检查项未完成（已完成的部分已保留）")
	}
	summary := compliance.Summarize(results)

	report := Report{
		TargetID:  targetID,
		Target:    fmt.Sprintf("%s@%s", target.Username, target.Host),
		StartedAt: started.UnixMilli(),
		ElapsedMs: time.Since(started).Milliseconds(),
		Summary:   summary,
		Results:   results,
		Problems:  problems,
	}

	// 落库留存：报告原本只活在前端页面上，切个目标或关掉页面就没了，
	// "这台机器上次什么结论"根本回答不了，也没法做前后对比。
	if s.store != nil {
		if payload, err := json.Marshal(results); err == nil {
			id, err := s.store.SaveComplianceReport(store.ComplianceReport{
				// 毫秒：与其他跨边界时间戳保持一致（之前这里写的是秒）
				TS: started.UnixMilli(), TargetID: targetID, Target: report.Target,
				Score: summary.Score, Total: summary.Total, Pass: summary.Pass,
				Fail: summary.Fail, Manual: summary.Manual, Error: summary.Error,
				ElapsedMs: report.ElapsedMs, Results: payload,
			})
			if err != nil {
				log.Printf("保存基线核查报告失败: %v", err)
			} else {
				report.ReportID = id
			}
		}
	}
	return report, nil
}

// History 返回某目标的核查历史。
func (s *ComplianceService) History(targetID string, limit int) ([]store.ComplianceReport, error) {
	if s.store == nil {
		return []store.ComplianceReport{}, nil
	}
	return s.store.ListComplianceReports(targetID, limit)
}

// ReportByID 取一份历史报告的完整内容。
func (s *ComplianceService) ReportByID(id int64) (*store.ComplianceReport, error) {
	if s.store == nil {
		return nil, fmt.Errorf("存储不可用")
	}
	return s.store.GetComplianceReport(id)
}

// DeleteReport 删掉一份核查报告，返回实际删掉的行数。
//
// 保留期清理是后台定时的事，用户还得能自己删掉某一次跑坏的结论。
func (s *ComplianceService) DeleteReport(id int64) (int64, error) {
	if s.store == nil {
		return 0, fmt.Errorf("存储不可用")
	}
	return s.store.DeleteComplianceReport(id)
}

// ClearReports 清空核查报告；targetID 为空表示全部清掉。
func (s *ComplianceService) ClearReports(targetID string) (int64, error) {
	if s.store == nil {
		return 0, fmt.Errorf("存储不可用")
	}
	return s.store.ClearComplianceReports(targetID)
}

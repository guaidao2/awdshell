package service

import (
	"encoding/json"
	"fmt"
	"log"
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

	checks, problems, err := s.Checks()
	if err != nil {
		return Report{}, err
	}

	started := time.Now()
	exec := func(cmd string, timeoutSec int) (string, error) {
		if timeoutSec <= 0 {
			timeoutSec = 10
		}
		// 单项命令返回非 0 很正常（比如文件不存在），不能因此丢掉整条连接
		return sshx.RunOutput(conn, cmd, time.Duration(timeoutSec)*time.Second)
	}
	results := compliance.Run(checks, exec, onlyIDs, nil)
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
				TS: started.Unix(), TargetID: targetID, Target: report.Target,
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

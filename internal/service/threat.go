package service

import (
	"log"
	"time"

	"github.com/guaidao2/awdshell/internal/store"
)

// ThreatService 提供跨目标、跨扫描次数的攻击态势聚合。
//
// 日志检测本身只看单次结果；态势要看的是"最近一周哪些 IP 在打、打的是谁、
// 打的是什么"，所以必须走落库的数据。
type ThreatService struct {
	store *store.Store
}

// NewThreatService 构造服务。
func NewThreatService(st *store.Store) *ThreatService {
	return &ThreatService{store: st}
}

// Stats 返回最近 days 天的态势聚合；targetID 非空时只统计这台主机。
func (s *ThreatService) Stats(days int, targetID string) (store.ThreatStats, error) {
	if days <= 0 {
		days = 7
	}
	if days > 365 {
		days = 365
	}
	// 事件时间戳统一用毫秒（与连接历史、核查报告一致）
	since := time.Now().AddDate(0, 0, -days).UnixMilli()
	return s.store.ThreatStats(since, targetID)
}

// EventCount 返回累计事件数。
func (s *ThreatService) EventCount() (int, error) {
	return s.store.ScanEventCount()
}

// ClearEvents 清空全部攻击事件，返回删除条数。
func (s *ThreatService) ClearEvents() (int64, error) {
	return s.store.ClearScanEvents()
}

// PruneEvents 清理超过保留期的事件。
func (s *ThreatService) PruneEvents(keepDays int) (int64, error) {
	if keepDays <= 0 {
		return 0, nil
	}
	before := time.Now().AddDate(0, 0, -keepDays).UnixMilli()
	n, err := s.store.PruneScanEvents(before)
	if err == nil && n > 0 {
		log.Printf("已清理 %d 条过期攻击事件", n)
	}
	return n, err
}

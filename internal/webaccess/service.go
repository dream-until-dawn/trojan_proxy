package webaccess

import (
	"context"
	"errors"
	"sync"
	"time"
)

type State struct {
	Available     bool   `json:"available"`
	Message       string `json:"message"`
	Backlog       int64  `json:"backlog_bytes"`
	Invalid       int64  `json:"invalid_records"`
	Gaps          int64  `json:"possible_gaps"`
	LastCollected int64  `json:"last_collected_ms"`
}

// Service 统计故障只影响访问页，不传播到认证、网站或VPN运行路径。
type Service struct {
	mu              sync.RWMutex
	store           *Store
	path, directory string
	state           State
}

func NewService(path, directory string) *Service {
	return &Service{path: path, directory: directory, state: State{Message: "访问记录正在初始化"}}
}
func (s *Service) State() State { s.mu.RLock(); defer s.mu.RUnlock(); return s.state }
func (s *Service) database() (*Store, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.store == nil {
		return nil, errors.New("访问库尚未就绪")
	}
	return s.store, nil
}
func (s *Service) Policy(ctx context.Context) (Policy, error) {
	db, err := s.database()
	if err != nil {
		return Policy{}, err
	}
	return db.Policy(ctx)
}
func (s *Service) SetWhitelist(ctx context.Context, revision uint64, cidrs []string) error {
	db, err := s.database()
	if err != nil {
		return err
	}
	return db.SetWhitelist(ctx, revision, cidrs, time.Now())
}
func (s *Service) Dashboard(ctx context.Context, f Filter) (Dashboard, error) {
	db, err := s.database()
	if err != nil {
		return Dashboard{}, err
	}
	return db.Dashboard(ctx, f, time.Now())
}

// Run 每秒读取有界批次，每分钟清理到期记录；请求处理不等待采集。
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastPrune time.Time
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.store != nil {
			s.store.Close()
			s.store = nil
		}
	}()
	for {
		if ctx.Err() != nil {
			return
		}
		check, cancel := context.WithTimeout(ctx, 2*time.Second)
		db, err := s.database()
		if err != nil {
			db, err = Open(check, s.path)
			if err == nil {
				s.mu.Lock()
				s.store = db
				s.mu.Unlock()
			}
		}
		state := s.State()
		if err == nil {
			now := time.Now()
			// 清理必须先于采集、且独立于上一轮采集结果。否则写满后一直采集失败，
			// 到期记录也永远无法释放空间，服务便不能自行恢复。
			if now.Sub(lastPrune) >= time.Minute {
				err = db.Prune(check, now)
				if err == nil {
					lastPrune = now
				}
			}
			if err == nil {
				state.Backlog, err = db.Collect(check, s.directory, now)
			}
			if err == nil {
				state.Invalid, state.Gaps, err = db.Diagnostics(check)
			}
			if err == nil {
				state.LastCollected = now.UnixMilli()
			}
		}
		state.Available = err == nil
		state.Message = "正在保存网站请求；白名单7天，其他来源30天"
		if err != nil {
			state.Message = "访问记录暂不可用或采集暂停；网站和VPN继续运行，请检查日志挂载、权限和容量"
		} else if state.Gaps > 0 || state.Invalid > 0 {
			state.Message = "存在采集间断或无效记录，历史可能不完整；请核对诊断计数"
		} else if state.Backlog > 0 {
			state.Message = "访问记录正在补采，请留意缓冲积压"
		}
		s.mu.Lock()
		s.state = state
		s.mu.Unlock()
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

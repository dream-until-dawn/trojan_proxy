package traffic

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrUnavailable = errors.New("统计暂不可用")

// Service 将统计初始化和重试隔离于控制面启动，磁盘异常不能拖垮认证和代理。
type Service struct {
	mu        sync.RWMutex
	path      string
	source    Source
	collector *Collector
}

func NewService(path string, source Source) *Service { return &Service{path: path, source: source} }

// Run 仅在独立工作协程调用，关闭前等待其退出；初始化失败每30秒重试。
func (s *Service) Run(ctx context.Context) {
	for ctx.Err() == nil {
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		store, err := Open(bounded, s.path)
		cancel()
		if err != nil {
			timer := time.NewTimer(30 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				continue
			}
		}
		collector := NewCollector(store, s.source)
		s.mu.Lock()
		s.collector = collector
		s.mu.Unlock()
		collector.Run(ctx)
		s.mu.Lock()
		s.collector = nil
		s.mu.Unlock()
		store.Close()
	}
}

// State 只返回实时速度与采集状态，目的IP需通过单独鉴权的历史接口查询。
func (s *Service) State() Live {
	s.mu.RLock()
	collector := s.collector
	s.mu.RUnlock()
	if collector == nil {
		return Live{Message: "统计初始化未完成或暂不可用"}
	}
	return collector.State()
}
func (s *Service) Dashboard(ctx context.Context, hours, offset int) (Dashboard, error) {
	s.mu.RLock()
	collector := s.collector
	s.mu.RUnlock()
	if collector == nil {
		return Dashboard{}, ErrUnavailable
	}
	return collector.Dashboard(ctx, hours, offset)
}

// Clear 只清空统计，不触碰账户/证书/规则；调用方须要求近期双因素认证。
func (s *Service) Clear(ctx context.Context) error {
	s.mu.RLock()
	collector := s.collector
	s.mu.RUnlock()
	if collector == nil {
		return ErrUnavailable
	}
	collector.pollMu.Lock()
	defer collector.pollMu.Unlock()
	if err := collector.store.Clear(ctx, collector.now()); err != nil {
		return err
	}
	return collector.store.Purge(ctx, collector.now())
}

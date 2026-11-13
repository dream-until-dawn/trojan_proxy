package auth

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

var (
	ErrCredentials = errors.New("口令或验证码错误")
	ErrLimited     = errors.New("登录请求过于频繁，请稍后重试")
	ErrUnavailable = errors.New("认证服务尚未就绪")
)

// AccountStore 把TOTP/恢复码消费交给持久化原子操作。
type AccountStore interface {
	Account(context.Context) (storage.Account, error)
	ConsumeTOTP(context.Context, int64, int64) (bool, error)
	ConsumeRecovery(context.Context, string) (bool, error)
}

type session struct {
	created, last time.Time
	endpoint      string
}

// Service 持有短期内存会话；进程重启后所有旧令牌自然失效。
type Service struct {
	store        AccountStore
	key          []byte
	budget       chan struct{}
	mu           sync.Mutex
	sessions     map[string]session
	failures     int
	blockedUntil time.Time
	now          func() time.Time
}

// NewService 为单管理员限制散列并发为1，避免64MiB乘以恶意并发。
func NewService(store AccountStore, key []byte) *Service {
	return &Service{store: store, key: append([]byte(nil), key...), budget: make(chan struct{}, 1), sessions: map[string]session{}, now: time.Now}
}

// Login 验证口令与TOTP或恢复码；凭据消费成功之后才签发会话。
func (s *Service) Login(ctx context.Context, password, otp, recovery string) (string, error) {
	select {
	case s.budget <- struct{}{}:
		defer func() { <-s.budget }()
	default:
		return "", ErrLimited
	}
	now := s.now()
	s.mu.Lock()
	blocked := now.Before(s.blockedUntil)
	s.mu.Unlock()
	if blocked {
		return "", ErrLimited
	}
	a, err := s.store.Account(ctx)
	if err != nil {
		return "", ErrUnavailable
	}
	valid := VerifyPassword(a.PasswordHash, password)
	if valid {
		if recovery != "" {
			valid, err = s.store.ConsumeRecovery(ctx, TokenHash(recovery))
		} else {
			secret, decryptErr := DecryptSecret(s.key, a.Secret)
			if decryptErr != nil {
				return "", ErrUnavailable
			}
			counter, matched := VerifyTOTP(secret, otp, now, a.LastCounter)
			valid = matched
			if valid {
				valid, err = s.store.ConsumeTOTP(ctx, a.LastCounter, counter)
			}
		}
	}
	if err != nil {
		return "", ErrUnavailable
	}
	if !valid {
		s.mu.Lock()
		s.failures++
		if s.failures >= 5 {
			s.blockedUntil = now.Add(time.Minute)
			s.failures = 0
		}
		s.mu.Unlock()
		return "", ErrCredentials
	}
	token, err := RandomToken()
	if err != nil {
		return "", ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, state := range s.sessions {
		if now.Sub(state.last) >= 30*time.Minute || now.Sub(state.created) >= 12*time.Hour {
			delete(s.sessions, hash)
		}
	}
	if len(s.sessions) >= 64 {
		s.sessions = map[string]session{}
	}
	s.sessions[TokenHash(token)] = session{created: now, last: now}
	s.failures = 0
	return token, nil
}

// LoginAt 将双因素会话绑定到服务器选中的完整入口；绑定不接受客户端自选身份。
func (s *Service) LoginAt(ctx context.Context, password, otp, recovery, endpoint string) (string, error) {
	if endpoint == "" {
		return "", ErrUnavailable
	}
	token, err := s.Login(ctx, password, otp, recovery)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	state := s.sessions[TokenHash(token)]
	state.endpoint = endpoint
	s.sessions[TokenHash(token)] = state
	s.mu.Unlock()
	return token, nil
}

// ValidateAt 同时校验会话入口和期限；被动轮询不续期，错误入口也不能续期。
func (s *Service) ValidateAt(token, endpoint string, passive bool) bool {
	if endpoint == "" {
		return false
	}
	return s.validateAt(token, !passive, endpoint)
}

// Validate 检查并滑动空闲期限，最长12小时不滑动。
func (s *Service) Validate(token string) bool {
	return s.validate(token, true)
}

// ValidatePassive 用于后台自动轮询，不把无人操作的页面永久续成活跃会话。
func (s *Service) ValidatePassive(token string) bool { return s.validate(token, false) }

func (s *Service) validate(token string, touch bool) bool {
	return s.validateAt(token, touch, "")
}

func (s *Service) validateAt(token string, touch bool, endpoint string) bool {
	if len(token) != 43 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := TokenHash(token)
	state, ok := s.sessions[hash]
	if !ok {
		return false
	}
	if endpoint != "" && state.endpoint != endpoint {
		return false
	}
	now := s.now()
	if now.Sub(state.last) >= 30*time.Minute || now.Sub(state.created) >= 12*time.Hour {
		delete(s.sessions, hash)
		return false
	}
	if touch {
		state.last = now
		s.sessions[hash] = state
	}
	return true
}

// Logout 立即撤销指定会话。
func (s *Service) Logout(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, TokenHash(token))
}

// Recent 要求敏感配置修改发生在最近一次双因素登录后的五分钟内。
func (s *Service) Recent(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.sessions[TokenHash(token)]
	return ok && s.now().Sub(state.created) < 5*time.Minute
}

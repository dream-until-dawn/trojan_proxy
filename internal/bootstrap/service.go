// Package bootstrap 实现仅供本机隧道使用的首次管理员绑定，不签发普通后台会话。
package bootstrap

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/url"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

// Store 负责跨进程条件更新；服务内并发预算不能代替持久化一次消费。
type Store interface {
	Setup(context.Context, time.Time) (storage.SetupState, error)
	SwapSetup(context.Context, storage.SetupState, storage.SetupState, time.Time) error
	CompleteSetup(context.Context, storage.SetupState, int64, time.Time) error
}

var ErrInput = errors.New("绑定信息不完整，或验证码错误；请确认已保存恢复码")

// Service 保留固定散列并发预算；单个有效绑定最多允许五次错误验证码。
type Service struct {
	store  Store
	key    []byte
	budget chan struct{}
	now    func() time.Time
}

// New 不从请求获取主密钥、路径或允许来源。
func New(store Store, key []byte) *Service {
	return &Service{store: store, key: append([]byte(nil), key...), budget: make(chan struct{}, 1), now: time.Now}
}

// Enrollment 是唯一一次显示的材料，只能经本机来源返回，不能打印到日志。
type Enrollment struct {
	Session  string   `json:"session"`
	Secret   string   `json:"secret"`
	URI      string   `json:"uri"`
	Recovery []string `json:"recovery"`
	Expires  int64    `json:"expires"`
}

func matches(token, expected string) bool {
	return len(token) == 43 && len(expected) == 64 && subtle.ConstantTimeCompare([]byte(auth.TokenHash(token)), []byte(expected)) == 1
}

// Begin 先校验随机令牌再花费口令散列成本；返回秘密前原子消费令牌。
func (s *Service) Begin(ctx context.Context, token, password string) (Enrollment, error) {
	select {
	case s.budget <- struct{}{}:
		defer func() { <-s.budget }()
	default:
		return Enrollment{}, auth.ErrLimited
	}
	state, err := s.store.Setup(ctx, s.now())
	if err != nil || !matches(token, state.TokenHash) {
		return Enrollment{}, storage.ErrSetupState
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return Enrollment{}, err
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return Enrollment{}, err
	}
	encrypted, err := auth.EncryptSecret(s.key, secret)
	if err != nil {
		return Enrollment{}, err
	}
	session, err := auth.RandomToken()
	if err != nil {
		return Enrollment{}, err
	}
	var codes, hashes []string
	for range 8 {
		code, err := auth.RandomToken()
		if err != nil {
			return Enrollment{}, err
		}
		codes = append(codes, code)
		hashes = append(hashes, auth.TokenHash(code))
	}
	next := storage.SetupState{SessionHash: auth.TokenHash(session), Expires: state.Expires,
		Account: storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: -1, Recovery: hashes}}
	if err = s.store.SwapSetup(ctx, state, next, s.now()); err != nil {
		return Enrollment{}, err
	}
	uri := "otpauth://totp/" + url.PathEscape("Trojan Proxy:administrator") + "?secret=" + secret + "&issuer=Trojan%20Proxy&algorithm=SHA1&digits=6&period=30"
	return Enrollment{Session: session, Secret: secret, URI: uri, Recovery: codes, Expires: next.Expires}, nil
}

// Finish 验证确认和TOTP，并在唯一账户创建事务中消费绑定状态与OTP步长。
func (s *Service) Finish(ctx context.Context, session, otp string, saved bool) error {
	if !saved {
		return ErrInput
	}
	state, err := s.store.Setup(ctx, s.now())
	if err != nil || !matches(session, state.SessionHash) || state.Failures >= 5 {
		return storage.ErrSetupState
	}
	secret, err := auth.DecryptSecret(s.key, state.Account.Secret)
	if err != nil {
		return auth.ErrUnavailable
	}
	counter, ok := auth.VerifyTOTP(secret, otp, s.now(), -1)
	if !ok {
		next := state
		next.Failures++
		if err = s.store.SwapSetup(ctx, state, next, s.now()); err != nil {
			return err
		}
		return ErrInput
	}
	return s.store.CompleteSetup(ctx, state, counter, s.now())
}

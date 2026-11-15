package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// CredentialBinding 将独立授权绑定管理员凭据代次，不包含验证码计数或恢复码消费状态。
// 重置/恢复会更换散列或TOTP密文，旧订阅自动失效；普通登录不改变绑定。
func (s *Service) CredentialBinding(ctx context.Context) (string, error) {
	if len(s.key) != 32 {
		return "", ErrUnavailable
	}
	a, err := s.store.Account(ctx)
	if err != nil || a.PasswordHash == "" || len(a.Secret) == 0 {
		return "", ErrUnavailable
	}
	body, err := json.Marshal(struct {
		PasswordHash string
		Secret       []byte
	}{a.PasswordHash, a.Secret})
	if err != nil {
		return "", ErrUnavailable
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("trojan-proxy/subscription-owner/v1\x00"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

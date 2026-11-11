package auth

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func TestPersistentLoginAndReplay(t *testing.T) {
	ctx := context.Background()
	s, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "state.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := make([]byte, 32)
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword("probe-strong-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CreateAccount(ctx, storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: -1, Recovery: []string{TokenHash("recovery-test-code")}}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1234567890, 0)
	service := NewService(s, key)
	service.now = func() time.Time { return now }
	// 恢复码必须配合正确口令，失败不能消费恢复码。
	if _, err = service.Login(ctx, "wrong-password", "", "recovery-test-code"); err != ErrCredentials {
		t.Fatal("错误口令未拒绝", err)
	}
	token, err := service.Login(ctx, "probe-strong-password-123", "", "recovery-test-code")
	if err != nil {
		t.Fatal(err)
	}
	if !service.Validate(token) {
		t.Fatal("有效令牌拒绝")
	}
	if _, err = service.Login(ctx, "probe-strong-password-123", "", "recovery-test-code"); err != ErrCredentials {
		t.Fatal("恢复码重放未拒绝", err)
	}
	if NewService(s, key).Validate(token) {
		t.Fatal("重启后旧令牌仍有效")
	}
	service.Logout(token)
	if service.Validate(token) {
		t.Fatal("退出后会话仍有效")
	}
	token, err = RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	service.sessions[TokenHash(token)] = session{created: now, last: now}
	now = now.Add(30 * time.Minute)
	if service.Validate(token) {
		t.Fatal("空闲过期未生效")
	}
	// 直接消费计数模拟两个并发验证者：第二个必须失败。
	ok, err := s.ConsumeTOTP(ctx, -1, 41152263)
	if err != nil || !ok {
		t.Fatal("首次消费失败", err)
	}
	if ok, err = s.ConsumeTOTP(ctx, -1, 41152263); err != nil || ok {
		t.Fatal("并发重放通过", err)
	}
}

func TestPassivePollingDoesNotExtendIdleSession(t *testing.T) {
	now := time.Unix(1800000000, 0)
	start := now
	service := NewService(nil, make([]byte, 32))
	service.now = func() time.Time { return now }
	token, err := RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	service.sessions[TokenHash(token)] = session{created: start, last: start}
	now = start.Add(29 * time.Minute)
	if !service.ValidatePassive(token) {
		t.Fatal("passive read rejected valid session")
	}
	now = start.Add(30 * time.Minute)
	if service.ValidatePassive(token) {
		t.Fatal("background polling extended idle session")
	}
	service.sessions[TokenHash(token)] = session{created: now, last: now}
	now = now.Add(29 * time.Minute)
	if !service.Validate(token) {
		t.Fatal("active request failed")
	}
	now = now.Add(2 * time.Minute)
	if !service.ValidatePassive(token) {
		t.Fatal("active request did not extend idle deadline")
	}
}

func TestVaultIntegrity(t *testing.T) {
	key := make([]byte, 32)
	encrypted, err := EncryptSecret(key, "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := DecryptSecret(key, encrypted); err != nil || plain != "test-secret" {
		t.Fatal("密文往返失败", err)
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, err = DecryptSecret(key, encrypted); err == nil {
		t.Fatal("篡改密文未拒绝")
	}
	if _, err = DecryptSecret(key, []byte("short")); err == nil {
		t.Fatal("截断密文未拒绝")
	}
}

func TestLoginBudgetAndBackoff(t *testing.T) {
	ctx := context.Background()
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "state.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := EncryptSecret(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := HashPassword("test-long-password-for-budget")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CreateAccount(ctx, storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: -1}); err != nil {
		t.Fatal(err)
	}
	s := NewService(db, key)
	now := time.Unix(1234567890, 0)
	s.now = func() time.Time { return now }
	s.budget <- struct{}{}
	if _, err = s.Login(ctx, "wrong", "", ""); err != ErrLimited {
		t.Fatal("并发预算未限制", err)
	}
	<-s.budget
	for range 5 {
		if _, err = s.Login(ctx, "wrong", "", ""); err != ErrCredentials {
			t.Fatal(err)
		}
	}
	if _, err = s.Login(ctx, "wrong", "", ""); err != ErrLimited {
		t.Fatal("失败退避未生效", err)
	}
	now = now.Add(61 * time.Second)
	if _, err = s.Login(ctx, "wrong", "", ""); err != ErrCredentials {
		t.Fatal("退避到期未恢复", err)
	}
}

package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

type bindingStore struct {
	account storage.Account
	err     error
}

func (s *bindingStore) Account(context.Context) (storage.Account, error)        { return s.account, s.err }
func (s *bindingStore) ConsumeTOTP(context.Context, int64, int64) (bool, error) { return false, nil }
func (s *bindingStore) ConsumeRecovery(context.Context, string) (bool, error)   { return false, nil }

func TestCredentialBindingTracksResetNotCounterConsumption(t *testing.T) {
	ctx := context.Background()
	store := &bindingStore{account: storage.Account{PasswordHash: "fixture-hash", Secret: []byte("encrypted-fixture"), LastCounter: 1, Recovery: []string{"one"}}}
	service := NewService(store, make([]byte, 32))
	first, err := service.CredentialBinding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store.account.LastCounter++
	store.account.Recovery = nil
	current, err := service.CredentialBinding(ctx)
	if err != nil || current != first {
		t.Fatal("normal MFA consumption invalidated subscription", err)
	}
	store.account.PasswordHash = "new-reset-hash"
	current, err = service.CredentialBinding(ctx)
	if err != nil || current == first {
		t.Fatal("administrator reset retained subscription generation", err)
	}
	store.account.PasswordHash = "fixture-hash"
	store.account.Secret = []byte("new-encrypted-fixture")
	current, _ = service.CredentialBinding(ctx)
	if current == first {
		t.Fatal("TOTP replacement retained subscription generation")
	}
	store.err = errors.New("unavailable")
	if _, err = service.CredentialBinding(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unavailable owner accepted", err)
	}
	store.err = nil
	store.account.PasswordHash = ""
	if _, err = service.CredentialBinding(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("uninitialized owner accepted", err)
	}
}

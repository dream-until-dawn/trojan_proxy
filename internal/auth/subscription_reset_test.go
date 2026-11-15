package auth_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"github.com/dream-until-dawn/trojan_proxy/internal/subscription"
)

// 使用真实账号库和离线重置流程，证明普通登录保留授权、重置后旧链接失效。
func TestSubscriptionSurvivesLoginButNotOfflineReset(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db, err := storage.OpenJournal(ctx, filepath.Join(dir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	account := func(password string) storage.Account {
		t.Helper()
		secret, e := auth.NewTOTPSecret()
		if e != nil {
			t.Fatal(e)
		}
		encrypted, e := auth.EncryptSecret(key, secret)
		if e != nil {
			t.Fatal(e)
		}
		hash, e := auth.HashPassword(password)
		if e != nil {
			t.Fatal(e)
		}
		codes := make([]string, 8)
		for i := range codes {
			codes[i] = auth.TokenHash(password + string(rune('a'+i)))
		}
		return storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: 0, Recovery: codes}
	}
	if err = db.CreateAccount(ctx, account("old-subscription-fixture")); err != nil {
		t.Fatal(err)
	}
	authentication := auth.NewService(db, key)
	store, err := subscription.Open(ctx, filepath.Join(dir, "subscription.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := subscription.New(store, authentication.CredentialBinding, func(context.Context) ([]byte, error) { return []byte("fixture-profile"), nil })
	_, token, err := service.Create(ctx, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authentication.Login(ctx, "old-subscription-fixture", "", "old-subscription-fixturea"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Fetch(ctx, token); err != nil {
		t.Fatal("normal login invalidated subscription", err)
	}
	if err = db.ResetAccount(ctx, account("new-subscription-fixture")); err != nil {
		t.Fatal(err)
	}
	if body, err := service.Fetch(ctx, token); !errors.Is(err, subscription.ErrDenied) || len(body) != 0 {
		t.Fatal("offline reset retained subscription authorization", err)
	}
}

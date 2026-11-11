package storage_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func TestOfflineAccountResetReplacesCredentialsButKeepsBusiness(t *testing.T) {
	ctx := context.Background()
	key := make([]byte, 32)
	oldSecret, _ := auth.NewTOTPSecret()
	oldEncrypted, _ := auth.EncryptSecret(key, oldSecret)
	oldHash, err := auth.HashPassword("old-fixture-password-only")
	if err != nil {
		t.Fatal(err)
	}
	initial := control.Revision{Number: 7, Gateway: "unchanged-gateway", VPN: "unchanged-vpn", Rules: "unchanged-rules"}
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), initial)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.CreateAccount(ctx, storage.Account{PasswordHash: oldHash, Secret: oldEncrypted, LastCounter: 321, Recovery: []string{auth.TokenHash("old-fixture-recovery")}}); err != nil {
		t.Fatal(err)
	}
	previousService := auth.NewService(db, key)
	oldToken, err := previousService.Login(ctx, "old-fixture-password-only", "", "old-fixture-recovery")
	if err != nil {
		t.Fatal(err)
	}
	newSecret, _ := auth.NewTOTPSecret()
	newEncrypted, _ := auth.EncryptSecret(key, newSecret)
	newHash, err := auth.HashPassword("new-fixture-password-only")
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{}
	for i := 0; i < 8; i++ {
		codes = append(codes, auth.TokenHash("new-code-"+string(rune('a'+i))))
	}
	if err = db.ResetAccount(ctx, storage.Account{PasswordHash: newHash, Secret: newEncrypted, LastCounter: 999, Recovery: codes}); err != nil {
		t.Fatal(err)
	}
	a, err := db.Account(ctx)
	if err != nil || a.LastCounter != 999 || bytes.Equal(a.Secret, oldEncrypted) || auth.VerifyPassword(a.PasswordHash, "old-fixture-password-only") || !auth.VerifyPassword(a.PasswordHash, "new-fixture-password-only") {
		t.Fatal("offline reset retained old credential material", err)
	}
	j, err := db.Load(ctx)
	if err != nil || j.Applied != initial {
		t.Fatal("account reset changed business revision", err)
	}
	// 独占维护锁要求旧进程已经停止，新控制进程不能接受旧内存会话。
	restarted := auth.NewService(db, key)
	if restarted.Validate(oldToken) {
		t.Fatal("new process accepted pre-reset session")
	}
	if _, err = restarted.Login(ctx, "new-fixture-password-only", "", "old-fixture-recovery"); err == nil {
		t.Fatal("old recovery code resurrected after reset")
	}
	if _, err = restarted.Login(ctx, "new-fixture-password-only", "", "new-code-a"); err != nil {
		t.Fatal("new recovery credential unusable", err)
	}
	if err = db.ResetAccount(ctx, storage.Account{PasswordHash: newHash, Secret: newEncrypted, LastCounter: 999, Recovery: codes[:7]}); err == nil {
		t.Fatal("incomplete reset credentials accepted")
	}
}

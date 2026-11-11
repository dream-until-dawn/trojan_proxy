package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

func TestSetupAcrossConnectionsAndReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	open := func() *JournalStore {
		t.Helper()
		s, err := OpenJournal(ctx, path, control.Revision{Number: 1})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	a, b := open(), open()
	defer b.Close()
	now := time.Now()
	if err := a.IssueSetup(ctx, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	state, err := a.Setup(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	next := state
	next.TokenHash = ""
	next.SessionHash = "session-hash"
	next.Account = Account{PasswordHash: "password-hash", Secret: []byte("ciphertext"), LastCounter: -1, Recovery: []string{"hashed-recovery"}}
	if err = b.SwapSetup(ctx, state, next, now); err != nil {
		t.Fatal(err)
	}
	if err = a.SwapSetup(ctx, state, next, now); err == nil {
		t.Fatal("stale setup snapshot overwrote another connection")
	}
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	a = open()
	defer a.Close()
	loaded, err := a.Setup(ctx, now)
	if err != nil || loaded.TokenHash != "" || loaded.SessionHash != next.SessionHash {
		t.Fatal("consumed token revived on database reopen", err)
	}
	if err = a.CompleteSetup(ctx, loaded, 123, now); err != nil {
		t.Fatal(err)
	}
	if err = b.CompleteSetup(ctx, loaded, 124, now); err == nil {
		t.Fatal("completed enrollment replay accepted across connections")
	}
	account, err := b.Account(ctx)
	if err != nil || account.LastCounter != 123 {
		t.Fatal("account changed after replay", err)
	}
}

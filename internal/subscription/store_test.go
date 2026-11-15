package subscription

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "subscription.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestTokenPersistenceRevocationExpiryAndOwnerIsolation(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	owner := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	r, token, err := s.Create(ctx, owner, "电脑")
	if err != nil {
		t.Fatal(err)
	}
	if !validToken(token) || len(r.ID) != 22 {
		t.Fatal("invalid generated token")
	}
	if err = s.Validate(ctx, owner, token); err != nil {
		t.Fatal("valid subscription rejected", err)
	}
	for _, bad := range []string{"", token + "x", strings.Repeat("A", 43)} {
		if err = s.Validate(ctx, owner, bad); !errors.Is(err, ErrDenied) {
			t.Fatal("invalid token accepted", err)
		}
	}
	if err = s.Validate(ctx, other, token); !errors.Is(err, ErrDenied) {
		t.Fatal("credential generation bypass", err)
	}
	var digest string
	if err = s.db.QueryRow("SELECT digest FROM tokens WHERE id=?", r.ID).Scan(&digest); err != nil || digest != tokenDigest(token) {
		t.Fatal("token not stored as digest", err)
	}
	list, err := s.List(ctx, owner)
	if err != nil || len(list) != 1 || list[0].Name != "电脑" {
		t.Fatal("device list mismatch", list, err)
	}
	path := s.dbPathForTest(t)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, path + "-journal"} {
		if b, e := os.ReadFile(file); e == nil && bytes.Contains(b, []byte(token)) {
			t.Fatal("raw subscription token persisted")
		}
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return now }
	if err = reopened.Validate(ctx, owner, token); err != nil {
		t.Fatal("restart lost valid token", err)
	}
	now = r.ExpiresAt.Add(-time.Second)
	if err = reopened.Validate(ctx, owner, token); err != nil {
		t.Fatal("token expired early", err)
	}
	now = r.ExpiresAt
	if err = reopened.Validate(ctx, owner, token); !errors.Is(err, ErrDenied) {
		t.Fatal("expired token accepted", err)
	}
	now = r.CreatedAt
	if err = reopened.Revoke(ctx, other, r.ID); !errors.Is(err, ErrDenied) {
		t.Fatal("cross-owner revoke accepted", err)
	}
	if err = reopened.Revoke(ctx, owner, r.ID); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Validate(ctx, owner, token); !errors.Is(err, ErrDenied) {
		t.Fatal("revoked token accepted", err)
	}
}

func (s *Store) dbPathForTest(t *testing.T) string {
	t.Helper()
	rows, err := s.db.Query("PRAGMA database_list")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var seq int
	var name, path string
	if !rows.Next() {
		t.Fatal("DB missing")
	}
	if err = rows.Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestConcurrentDeviceLimitAndPruning(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	owner := strings.Repeat("a", 64)
	var accepted, limited atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := s.Create(ctx, owner, "设备")
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrLimit):
				limited.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 16 || limited.Load() != 16 {
		t.Fatal("device quota not enforced", accepted.Load(), limited.Load())
	}
	list, _ := s.List(ctx, owner)
	if err := s.Revoke(ctx, owner, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Create(ctx, owner, "新设备"); err != nil {
		t.Fatal("revocation did not free slot", err)
	}
	other := strings.Repeat("b", 64)
	if _, _, err := s.Create(ctx, other, "新管理员"); err != nil {
		t.Fatal(err)
	}
	var count int
	s.db.QueryRow("SELECT count(*) FROM tokens").Scan(&count)
	if count != 1 {
		t.Fatal("obsolete generation not pruned", count)
	}
	for _, name := range []string{"", strings.Repeat("名", 41), "a\nb", string([]byte{0xff})} {
		if _, _, err := s.Create(ctx, other, name); !errors.Is(err, ErrName) {
			t.Fatal("invalid name accepted", err)
		}
	}
}

func TestFetchRechecksRevocationAfterExport(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	owner := strings.Repeat("a", 64)
	r, token, err := s.Create(ctx, owner, "设备")
	if err != nil {
		t.Fatal(err)
	}
	service := New(s, func(context.Context) (string, error) { return owner, nil }, func(context.Context) ([]byte, error) {
		if err := s.Revoke(ctx, owner, r.ID); err != nil {
			t.Fatal(err)
		}
		return []byte("credential-sentinel"), nil
	})
	body, err := service.Fetch(ctx, token)
	if !errors.Is(err, ErrDenied) || len(body) != 0 {
		t.Fatal("revoked-during-export subscription leaked profile", err)
	}
}

func TestFetchBudgetRejectsExcessWithoutExport(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	owner := strings.Repeat("a", 64)
	_, token, _ := s.Create(ctx, owner, "设备")
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan error, 2)
	service := New(s, func(context.Context) (string, error) { return owner, nil }, func(context.Context) ([]byte, error) { started <- struct{}{}; <-release; return []byte("profile"), nil })
	for i := 0; i < 2; i++ {
		go func() { _, err := service.Fetch(ctx, token); done <- err }()
	}
	<-started
	<-started
	if _, err := service.Fetch(ctx, token); !errors.Is(err, ErrLimit) {
		t.Fatal("fetch budget not enforced", err)
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

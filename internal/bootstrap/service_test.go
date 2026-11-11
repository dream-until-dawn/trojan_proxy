package bootstrap

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func fixture(t *testing.T) (*Service, *storage.JournalStore, string, time.Time) {
	t.Helper()
	db, err := storage.OpenJournal(context.Background(), filepath.Join(t.TempDir(), "state.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	now := time.Unix(1800000000, 0)
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if err = db.IssueSetup(context.Background(), auth.TokenHash(token), now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	s := New(db, make([]byte, 32))
	s.now = func() time.Time { return now }
	return s, db, token, now
}

// 独立实现测试侧标准TOTP，不调用被测VerifyTOTP计算期望值。
func otp(secret string, now time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(now.Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(b[:])
	d := m.Sum(nil)
	off := d[len(d)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(d[off:off+4])&0x7fffffff)%1000000)
}

func TestEnrollmentPersistentSingleUseAndLogin(t *testing.T) {
	s, db, token, now := fixture(t)
	ctx := context.Background()
	if _, err := s.Begin(ctx, "wrong", "test-password-at-least-sixteen"); err == nil {
		t.Fatal("invalid setup token accepted")
	}
	if _, err := s.Begin(ctx, token, "weak"); err == nil {
		t.Fatal("weak password accepted")
	}
	e, err := s.Begin(ctx, token, "test-password-at-least-sixteen")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Recovery) != 8 || e.Secret == "" || e.Session == "" {
		t.Fatal("missing enrollment material")
	}
	// 新服务实例仍不得重用已消费的token，防止仅依赖内存标志的伪保护。
	restarted := New(db, make([]byte, 32))
	restarted.now = s.now
	if _, err = restarted.Begin(ctx, token, "test-password-at-least-sixteen"); err == nil {
		t.Fatal("consumed token replay accepted after restart")
	}
	if err = s.Finish(ctx, e.Session, otp(e.Secret, now), false); err == nil {
		t.Fatal("missing recovery confirmation accepted")
	}
	if err = restarted.Finish(ctx, e.Session, otp(e.Secret, now), true); err != nil {
		t.Fatal(err)
	}
	before, err := db.Account(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(before.PasswordHash, "test-password-at-least-sixteen") {
		t.Fatal("password not persisted correctly")
	}
	if before.LastCounter != now.Unix()/30 {
		t.Fatal("binding OTP counter was not consumed")
	}
	if _, ok := auth.VerifyTOTP(e.Secret, otp(e.Secret, now), now, before.LastCounter); ok {
		t.Fatal("binding OTP replay accepted")
	}
	login := auth.NewService(db, make([]byte, 32))
	if _, err = login.Login(ctx, "test-password-at-least-sixteen", "", e.Recovery[0]); err != nil {
		t.Fatal("recovery login failed", err)
	}
	if _, err = login.Login(ctx, "test-password-at-least-sixteen", "", e.Recovery[0]); err == nil {
		t.Fatal("reused recovery accepted")
	}
	if err = restarted.Finish(ctx, e.Session, otp(e.Secret, now), true); err == nil {
		t.Fatal("completed session replay accepted")
	}
	if err = db.IssueSetup(ctx, auth.TokenHash(token), now.Add(time.Hour)); err == nil {
		t.Fatal("existing administrator can be re-enrolled")
	}
	if pending, err := db.HasSetup(ctx); err != nil || pending {
		t.Fatal("completed draft was retained", err)
	}
}

func TestExpiryAndPersistentFailureLimit(t *testing.T) {
	s, db, token, now := fixture(t)
	ctx := context.Background()
	s.now = func() time.Time { return now.Add(10 * time.Minute) }
	if _, err := s.Begin(ctx, token, "test-password-at-least-sixteen"); err == nil {
		t.Fatal("expired setup token accepted at exact boundary")
	}
	s.now = func() time.Time { return now }
	e, err := s.Begin(ctx, token, "test-password-at-least-sixteen")
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if err = s.Finish(ctx, e.Session, "bad", true); err == nil {
			t.Fatal("bad OTP accepted")
		}
	}
	restarted := New(db, make([]byte, 32))
	restarted.now = s.now
	if err = restarted.Finish(ctx, e.Session, otp(e.Secret, now), true); err == nil {
		t.Fatal("failure limit bypassed by service restart")
	}
	if ready, err := db.Initialized(ctx); err != nil || ready {
		t.Fatal("failed enrollment created account", err)
	}
}

func TestConcurrentServicesAndAccountCreation(t *testing.T) {
	s, db, token, now := fixture(t)
	ctx := context.Background()
	other := New(db, make([]byte, 32))
	other.now = s.now
	var successes atomic.Int32
	var mu sync.Mutex
	var winner Enrollment
	var wg sync.WaitGroup
	for _, service := range []*Service{s, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := service.Begin(ctx, token, "test-password-at-least-sixteen")
			if err == nil {
				successes.Add(1)
				mu.Lock()
				winner = e
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent begin successes=%d", successes.Load())
	}
	successes.Store(0)
	for _, service := range []*Service{s, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if service.Finish(ctx, winner.Session, otp(winner.Secret, now), true) == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("concurrent finish successes=%d", successes.Load())
	}
}

func TestPendingSessionExpiryAndTerminalRace(t *testing.T) {
	s, db, token, now := fixture(t)
	ctx := context.Background()
	e, err := s.Begin(ctx, token, "test-password-at-least-sixteen")
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now.Add(10 * time.Minute) }
	if err = s.Finish(ctx, e.Session, otp(e.Secret, s.now()), true); err == nil {
		t.Fatal("expired session accepted")
	}
	s.now = func() time.Time { return now }
	terminal := storage.Account{PasswordHash: "terminal-hash", Secret: []byte("terminal-encrypted"), LastCounter: 123, Recovery: []string{"remaining-code"}}
	if err = db.CreateAccount(ctx, terminal); err != nil {
		t.Fatal(err)
	}
	if err = s.Finish(ctx, e.Session, otp(e.Secret, now), true); err == nil {
		t.Fatal("web enrollment overwrote terminal account")
	}
	a, err := db.Account(ctx)
	if err != nil || a.PasswordHash != terminal.PasswordHash || a.LastCounter != 123 {
		t.Fatal("terminal account changed", err)
	}
}

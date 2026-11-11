package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/bootstrap"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func testCode(secret string) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var value [8]byte
	binary.BigEndian.PutUint64(value[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(value[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1000000)
}

func TestBrowserBootstrapRealListenerLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	c := config.Config{DataDir: t.TempDir(), ControlPort: port - 2}
	db, err := storage.OpenJournal(ctx, filepath.Join(c.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	result := make(chan error, 1)
	go func() { _, err := prepareAdministrator(ctx, c, db); result <- err }()
	origin := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 2 * time.Second}
	ready := false
	for range 100 {
		response, e := client.Get(origin + "/")
		if e == nil {
			response.Body.Close()
			ready = response.StatusCode == 200
			if ready {
				break
			}
		}
		select {
		case err = <-result:
			t.Fatal("bootstrap exited before readiness", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("local bootstrap listener not ready")
	}
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	if err = db.IssueSetup(ctx, auth.TokenHash(token), time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	post := func(path string, body any, target any) {
		t.Helper()
		raw, _ := json.Marshal(body)
		request, _ := http.NewRequestWithContext(ctx, "POST", origin+path, bytes.NewReader(raw))
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		response, e := client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		if response.StatusCode != 200 {
			t.Fatal("setup HTTP status", response.StatusCode)
		}
		if target != nil {
			if e = json.NewDecoder(response.Body).Decode(target); e != nil {
				t.Fatal(e)
			}
		}
	}
	var enrollment bootstrap.Enrollment
	post("/api/setup/begin", map[string]string{"token": token, "password": "test-password-at-least-sixteen"}, &enrollment)
	post("/api/setup/finish", map[string]any{"session": enrollment.Session, "otp": testCode(enrollment.Secret), "saved": true}, nil)
	select {
	case err = <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("bootstrap listener did not close after completion")
	}
	if connection, e := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second); e == nil {
		connection.Close()
		t.Fatal("bootstrap listener remained open")
	}
	if _, err = prepareAdministrator(ctx, c, db); err != nil {
		t.Fatal("existing administrator reopened setup", err)
	}
	if err = os.Remove(filepath.Join(c.DataDir, "master.key")); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareAdministrator(ctx, c, db); err == nil {
		t.Fatal("missing key silently replaced for existing administrator")
	}
}

func TestMissingKeyWithPendingEnrollmentIsRejected(t *testing.T) {
	ctx := context.Background()
	c := config.Config{DataDir: t.TempDir(), ControlPort: 18090}
	db, err := storage.OpenJournal(ctx, filepath.Join(c.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err = db.IssueSetup(ctx, auth.TokenHash("fixture"), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareAdministrator(ctx, c, db); err == nil {
		t.Fatal("pending enrollment silently received a new master key")
	}
}

//go:build integration && linux

package deployment

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/bootstrap"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

const fixturePassword = "compose-disposable-fixture-password-only"

func otpFixture(secret string, counter int64) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
}

func TestDisposableComposeFlow(t *testing.T) {
	if os.Getenv("TROJAN_DISPOSABLE_COMPOSE_TEST") != "1" {
		t.Skip("仅对探针创建的隔离卷运行")
	}
	ctx := context.Background()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	post := func(port int, path, token string, input, output any) int {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		origin := fmt.Sprintf("http://127.0.0.1:%d", port)
		r, err := http.NewRequest("POST", origin+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("compose API unavailable", path, err)
		}
		defer response.Body.Close()
		if output != nil && response.StatusCode == 200 {
			if err = json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(output); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode
	}
	get := func(port int, path string) (int, string) {
		t.Helper()
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(body)
	}
	phase := os.Getenv("TROJAN_COMPOSE_PHASE")
	if phase == "first" {
		status, body := get(80, "/")
		if status != 200 || !strings.Contains(body, "欢迎访问") || strings.Contains(body, "VPN") || strings.Contains(body, "代理") {
			t.Fatal("fresh public welcome invalid", status)
		}
		if status, body = get(80, "/robots.txt"); status != 200 || body != "User-agent: *\nDisallow: /\n" {
			t.Fatal("fresh robots declaration missing", status)
		}
		db, err := storage.OpenJournal(ctx, "/data/control.db", control.Revision{Number: 1})
		if err != nil {
			t.Fatal(err)
		}
		token, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if err = db.IssueSetup(ctx, auth.TokenHash(token), time.Now().Add(10*time.Minute)); err != nil {
			t.Fatal(err)
		}
		db.Close()
		var enrollment bootstrap.Enrollment
		if status = post(18092, "/api/setup/begin", "", map[string]string{"token": token, "password": fixturePassword}, &enrollment); status != 200 {
			t.Fatal("compose browser enrollment failed", status)
		}
		if status = post(18092, "/api/setup/begin", "", map[string]string{"token": token, "password": fixturePassword}, nil); status != 400 {
			t.Fatal("compose setup token replay accepted", status)
		}
		if status = post(18092, "/api/setup/finish", "", map[string]any{"session": enrollment.Session, "otp": otpFixture(enrollment.Secret, time.Now().Unix()/30), "saved": true}, nil); status != 200 {
			t.Fatal("compose browser enrollment did not finish", status)
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			if response, err := client.Get("http://127.0.0.1:18090/healthz"); err == nil {
				response.Body.Close()
				if response.StatusCode == 200 {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("normal control listener did not replace setup")
			}
			time.Sleep(100 * time.Millisecond)
		}
		if connection, err := net.DialTimeout("tcp4", "127.0.0.1:18092", time.Second); err == nil {
			connection.Close()
			t.Fatal("setup listener remained after enrollment")
		}
		var login struct {
			Token string `json:"token"`
		}
		code := otpFixture(enrollment.Secret, time.Now().Unix()/30+1)
		if status = post(18090, "/api/login", "", map[string]string{"password": fixturePassword, "otp": code}, &login); status != 200 || login.Token == "" {
			t.Fatal("compose login failed", status)
		}
		if status = post(18090, "/api/login", "", map[string]string{"password": fixturePassword, "otp": code}, nil); status != 401 {
			t.Fatal("compose TOTP replay accepted", status)
		}
		var current struct {
			Revision uint64 `json:"revision"`
		}
		if status = post(18090, "/api/routes/list", login.Token, map[string]any{}, &current); status != 200 {
			t.Fatal(status)
		}
		ruleset := []routes.Rule{{ID: "backend", Name: "夹具服务", Port: 80, Path: "/app", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 19000}, {ID: "downloads", Name: "夹具目录", Port: 8001, Path: "/", Kind: "files", DirectoryID: "public"}}
		if status = post(18090, "/api/routes/apply", login.Token, map[string]any{"revision": current.Revision, "rules": ruleset}, nil); status != 200 {
			t.Fatal("compose route apply failed", status)
		}
		var state struct {
			Settings settings.Snapshot `json:"settings"`
		}
		if status = post(18090, "/api/settings/status", login.Token, map[string]any{}, &state); status != 200 {
			t.Fatal(status)
		}
		candidate := state.Settings.Site
		candidate.AdminPort = 8006
		candidate.VPNPort = 19443
		candidate.VPNAddresses = []string{"198.51.100.10"}
		if status = post(18090, "/api/settings/propose", login.Token, map[string]any{"revision": state.Settings.Revision, "site": candidate}, nil); status != 200 {
			t.Fatal("compose candidate proposal failed", status)
		}
		if status = post(18090, "/api/routes/apply", login.Token, map[string]any{"revision": state.Settings.Revision + 1, "rules": ruleset}, nil); status != 423 {
			t.Fatal("compose candidate failed to freeze route writes", status)
		}
		if status = post(18090, "/api/settings/status", login.Token, map[string]any{}, &state); status != 200 {
			t.Fatal(status)
		}
		if status = post(18090, "/api/settings/confirm", login.Token, map[string]any{"revision": state.Settings.Revision}, nil); status != 200 {
			t.Fatal("compose settings confirmation failed", status)
		}
	} else if phase != "verify" {
		t.Fatal("unknown disposable compose phase")
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		status, body := get(80, "/app/check")
		if status == 200 && body == "upstream-sentinel" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("compose proxy did not recover", status)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if status, body := get(8001, "/download.txt"); status != 200 || body != "readonly-file-sentinel" {
		t.Fatal("compose directory unavailable", status)
	}
	db, err := storage.OpenJournal(ctx, "/data/control.db", control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	j, err := db.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Site settings.Site `json:"site"`
	}
	if err = json.Unmarshal([]byte(j.Applied.Settings), &document); err != nil || document.Site.AdminPort != 8006 || document.Site.VPNPort != 19443 {
		t.Fatal("container recreation overwrote web settings", err)
	}
	account, err := db.Account(ctx)
	if err != nil || account.LastCounter < time.Now().Add(-5*time.Minute).Unix()/30 || len(account.Recovery) != 8 {
		t.Fatal("container recreation reset TOTP or recovery state", err)
	}
	if status := post(18090, "/api/settings/status", "invalid-fixture-token", map[string]any{}, nil); status != 401 {
		t.Fatal("compose settings bypassed authentication", status)
	}
}

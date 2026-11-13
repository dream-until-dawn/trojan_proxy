package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func TestSessionCannotMoveBetweenAdminEntries(t *testing.T) {
	ctx := context.Background()
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "state.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	secret, _ := auth.NewTOTPSecret()
	encrypted, _ := auth.EncryptSecret(key, secret)
	hash, err := auth.HashPassword("test-long-random-password")
	if err != nil {
		t.Fatal(err)
	}
	codes := []string{"entry-recovery-old", "entry-recovery-domain", "entry-recovery-path"}
	if err = db.CreateAccount(ctx, storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: -1,
		Recovery: []string{auth.TokenHash(codes[0]), auth.TokenHash(codes[1]), auth.TokenHash(codes[2])}}); err != nil {
		t.Fatal(err)
	}
	entries := []adminentry.Endpoint{{Origin: "https://example.com", Prefix: "/proxy"},
		{Origin: "https://proxy.example.com"}, {Origin: "https://example.com", Prefix: "/other-proxy"}}
	server := &Server{Auth: auth.NewService(db, key), EndpointsProvider: func() []adminentry.Endpoint { return entries }}
	handler := server.Handler()
	call := func(entry adminentry.Endpoint, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", entry.Identity()+path, strings.NewReader(body))
		r.Header.Set("Origin", entry.Origin)
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	tokens := make([]string, len(entries))
	for index, entry := range entries {
		body, _ := json.Marshal(map[string]string{"password": "test-long-random-password", "recovery": codes[index]})
		response := call(entry, "/api/login", "", string(body))
		if response.Code != 200 {
			t.Fatalf("entry login failed: %d", response.Code)
		}
		var result struct {
			Token string `json:"token"`
		}
		if err = json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Token == "" {
			t.Fatal("invalid token")
		}
		tokens[index] = result.Token
		if response = call(entry, "/api/status", result.Token, "{}"); response.Code != 200 {
			t.Fatal("own entry rejected", response.Code)
		}
	}
	for from, token := range tokens {
		for to, entry := range entries {
			if from == to {
				continue
			}
			for _, path := range []string{"/api/status", "/api/settings/confirm", "/api/traffic/live"} {
				if response := call(entry, path, token, "{}"); response.Code != 401 {
					t.Fatalf("old entry bearer authorized candidate: from=%d to=%d path=%s status=%d", from, to, path, response.Code)
				}
			}
		}
	}
	old := entries[0]
	entries = entries[1:]
	if response := call(old, "/api/status", tokens[0], "{}"); response.Code != 404 {
		t.Fatal("retired path accepted", response.Code)
	}
	if response := call(entries[0], "/api/status", tokens[0], "{}"); response.Code != 401 {
		t.Fatal("retired token moved to new domain", response.Code)
	}
}

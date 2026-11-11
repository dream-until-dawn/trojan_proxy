package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
)

type testCertificates struct {
	imports int
	fail    bool
}

func (m *testCertificates) Status(context.Context) (certificates.State, error) {
	return certificates.State{Available: true, Domain: "example.com", Ready: true}, nil
}
func (m *testCertificates) Import(string, []byte, []byte) (certificates.Prepared, error) {
	m.imports++
	if m.fail {
		return certificates.Prepared{}, errors.New("secret-private-key-sentinel")
	}
	return certificates.Prepared{Version: strings.Repeat("a", 64)}, nil
}

func TestCertificateImportAuthenticationBudgetAndNoSecretEcho(t *testing.T) {
	m := &testCertificates{}
	auth := &testAuthentication{}
	origin := "https://example.com:8007"
	h := (&Server{Auth: auth, Origins: map[string]bool{origin: true}, Certificates: m}).Handler()
	call := func(path, token, source, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Host = "example.com:8007"
		r.Header.Set("Origin", source)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body := `{"domain":"example.com","certificate":"fixture-chain","private_key":"secret-private-key-sentinel"}`
	for _, path := range []string{"/api/certificates/status", "/api/certificates/import"} {
		if w := call(path, "", origin, body); w.Code != 401 {
			t.Fatal("certificate endpoint bypassed authentication", path, w.Code)
		}
		if w := call(path, "fixture-session", "https://evil.example", body); w.Code != 403 {
			t.Fatal("certificate endpoint bypassed origin", path, w.Code)
		}
	}
	if w := call("/api/certificates/import", "fixture-session", origin, body); w.Code != 403 || m.imports != 0 {
		t.Fatal("certificate import bypassed recent MFA", w.Code)
	}
	auth.recent = true
	for _, bad := range []string{`{"domain":"example.com","path":"/etc/shadow"}`, body + ` {}`, `{"domain":"example.com","private_key":"` + strings.Repeat("a", 65537) + `"}`} {
		if w := call("/api/certificates/import", "fixture-session", origin, bad); w.Code != 400 || m.imports != 0 {
			t.Fatal("malformed certificate request reached publisher", w.Code, m.imports)
		}
	}
	if w := call("/api/certificates/import", "fixture-session", origin, body); w.Code != 200 || m.imports != 1 || strings.Contains(w.Body.String(), "secret-private-key-sentinel") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("certificate import response invalid", w.Code, w.Body.String())
	}
	m.fail = true
	if w := call("/api/certificates/import", "fixture-session", origin, body); w.Code != 400 || strings.Contains(w.Body.String(), "secret-private-key-sentinel") {
		t.Fatal("certificate failure leaked underlying secret", w.Code, w.Body.String())
	}
}

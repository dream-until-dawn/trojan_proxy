package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
)

func TestAdminDomainDoesNotTrustBusinessOrRetiredOrigin(t *testing.T) {
	entries := []adminentry.Endpoint{{Origin: "https://example.com", Prefix: "/proxy"}, {Origin: "https://proxy.example.com"}}
	h := (&Server{Auth: &testAuthentication{}, EndpointsProvider: func() []adminentry.Endpoint { return entries }}).Handler()
	call := func(host, path, origin, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader("{}"))
		r.Host = host
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call("proxy.example.com", "/api/status", "https://proxy.example.com", ""); w.Code != 401 {
		t.Fatal("admin domain bypassed authentication", w.Code)
	}
	if w := call("proxy.example.com", "/api/status", "https://example.com", "fixture-session"); w.Code != 403 {
		t.Fatal("old origin controlled new admin domain", w.Code)
	}
	if w := call("proxy.example.com", "/api/status", "https://proxy.example.com", "fixture-session"); w.Code != 200 {
		t.Fatal("new administrator origin rejected", w.Code)
	}
	entries = entries[1:]
	for _, host := range []string{"example.com", "one.example.com"} {
		if w := call(host, "/proxy/api/status", "https://"+host, "fixture-session"); w.Code != 421 {
			t.Fatal("business or retired host accessed administration", host, w.Code)
		}
	}
}

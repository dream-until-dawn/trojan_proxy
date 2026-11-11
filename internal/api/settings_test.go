package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
)

type testSettings struct{ proposals, confirms, cancels int }

func (s *testSettings) Status(context.Context) (settings.Snapshot, error) {
	return settings.Snapshot{Revision: 2, Site: settings.Site{Domain: "example.com", AdminPort: 8007}}, nil
}
func (s *testSettings) Propose(context.Context, uint64, settings.Site) error {
	s.proposals++
	return nil
}
func (s *testSettings) Confirm(context.Context, uint64, string) error { s.confirms++; return nil }
func (s *testSettings) Cancel(context.Context, uint64) error          { s.cancels++; return nil }

func TestSettingsAPIAuthenticationRecentMFAAndHostBinding(t *testing.T) {
	auth := &testAuthentication{}
	manager := &testSettings{}
	old, newOrigin := "https://example.com:8007", "https://example.com:8006"
	origins := map[string]bool{old: true, newOrigin: true}
	handler := (&Server{Auth: auth, Settings: manager, OriginProvider: func() map[string]bool { return origins }}).Handler()
	call := func(path, token, origin, host, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Host = host
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/settings/status", "/api/settings/propose", "/api/settings/confirm", "/api/settings/cancel"} {
		if w := call(path, "", old, "example.com:8007", "{}"); w.Code != 401 {
			t.Fatal("settings unauthenticated request accepted", path, w.Code)
		}
		if w := call(path, "fixture-session", "https://evil.example", "example.com:8007", "{}"); w.Code != 403 {
			t.Fatal("settings cross origin accepted", path, w.Code)
		}
	}
	for _, path := range []string{"/api/settings/propose", "/api/settings/confirm", "/api/settings/cancel"} {
		if w := call(path, "fixture-session", old, "example.com:8007", "{}"); w.Code != 403 {
			t.Fatal("settings recent MFA not required", path, w.Code)
		}
	}
	auth.recent = true
	if w := call("/api/settings/confirm", "fixture-session", newOrigin, "example.com:8007", `{"revision":2}`); w.Code != 403 || manager.confirms != 0 {
		t.Fatal("confirmation Origin and Host mismatch accepted", w.Code)
	}
	if w := call("/api/settings/confirm", "fixture-session", newOrigin, "example.com:8006", `{"revision":2}`); w.Code != 200 || manager.confirms != 1 {
		t.Fatal("valid confirmation failed", w.Code)
	}
	if w := call("/api/settings/propose", "fixture-session", old, "example.com:8007", `{"revision":2,"site":{"admin_port":8006}}`); w.Code != 200 || manager.proposals != 1 {
		t.Fatal("valid settings proposal failed", w.Code)
	}
	for _, body := range []string{`{"revision":2,"data_dir":"/etc"}`, `{"site":{"secret":"x"}}`, `{} {}`} {
		if w := call("/api/settings/propose", "fixture-session", old, "example.com:8007", body); w.Code != 400 {
			t.Fatal("unknown settings input accepted", w.Code)
		}
	}
	// 动态移除旧入口后旧来源必须立即失效，不能继续依赖构造时的白名单。
	origins = map[string]bool{newOrigin: true}
	if w := call("/api/settings/status", "fixture-session", old, "example.com:8007", "{}"); w.Code != 421 {
		t.Fatal("removed origin remained usable", w.Code)
	}
}

func TestEntryPendingFreezesBusinessWritesButNotReads(t *testing.T) {
	auth := &testAuthentication{recent: true}
	vpn := &testVPN{}
	origin := "https://example.com:8007"
	h := (&Server{Auth: auth, VPN: vpn, Origins: map[string]bool{origin: true}, WriteGuard: func(context.Context) error { return settings.ErrFrozen }}).Handler()
	for _, path := range []string{"/api/routes/apply", "/api/vpn/apply"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"revision":1,"enabled":false}`))
		r.Host = "example.com:8007"
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer fixture-session")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 423 {
			t.Fatal("entry pending write freeze bypassed", path, w.Code)
		}
	}
	if vpn.writes != 0 {
		t.Fatal("frozen VPN write still executed")
	}
	r := httptest.NewRequest("POST", "/api/vpn/status", strings.NewReader("{}"))
	r.Host = "example.com:8007"
	r.Header.Set("Origin", origin)
	r.Header.Set("Authorization", "Bearer fixture-session")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("pending entry froze status reads", w.Code)
	}
}

package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/traffic"
)

type testTraffic struct{ reads, clears int }

func (s *testTraffic) State() traffic.Live { return traffic.Live{Available: true, UploadBPS: 50} }
func (s *testTraffic) Dashboard(context.Context, int, int) (traffic.Dashboard, error) {
	s.reads++
	return traffic.Dashboard{RetentionDays: 30, Targets: []traffic.TargetTotals{{IP: "198.51.100.20", Upload: 123}}}, nil
}
func (s *testTraffic) Clear(context.Context) error { s.clears++; return nil }

func TestTrafficRecordsAreAuthenticatedAndBounded(t *testing.T) {
	manager := &testTraffic{}
	origin := "https://example.com:8007"
	handler := (&Server{Auth: &testAuthentication{}, Origins: map[string]bool{origin: true}, Traffic: manager}).Handler()
	call := func(path, token, source, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Host = "example.com:8007"
		r.Header.Set("Origin", source)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/traffic/live", "/api/traffic/dashboard"} {
		w := call(path, "", origin, `{"hours":24}`)
		if w.Code != 401 || strings.Contains(w.Body.String(), "198.51.100.20") {
			t.Fatal("traffic destination leaked without authentication", w.Code)
		}
		if w = call(path, "fixture-session", "https://evil.example", `{"hours":24}`); w.Code != 403 {
			t.Fatal("traffic cross-origin request accepted", w.Code)
		}
	}
	w := call("/api/traffic/dashboard", "fixture-session", origin, `{"hours":24}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "198.51.100.20") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated traffic dashboard unavailable or cacheable", w.Code)
	}
	for _, body := range []string{`{"hours":721}`, `{"hours":24,"offset":100000}`, `{"hours":24,"path":"/etc"}`, `{} {}`} {
		if w = call("/api/traffic/dashboard", "fixture-session", origin, body); w.Code != 400 {
			t.Fatal("unbounded or malformed traffic query accepted", w.Code)
		}
	}
	if manager.reads != 1 {
		t.Fatal("rejected traffic query reached database", manager.reads)
	}
}

func TestClearTrafficRequiresRecentMFAAndAcknowledgement(t *testing.T) {
	manager := &testTraffic{}
	auth := &testAuthentication{}
	origin := "https://example.com:8007"
	h := (&Server{Auth: auth, Origins: map[string]bool{origin: true}, Traffic: manager}).Handler()
	call := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/traffic/clear", strings.NewReader(body))
		r.Host = "example.com:8007"
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer fixture-session")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := call(`{"confirm":true}`); w.Code != 403 || manager.clears != 0 {
		t.Fatal("traffic clear recent MFA bypassed", w.Code)
	}
	auth.recent = true
	if w := call(`{"confirm":false}`); w.Code != 400 || manager.clears != 0 {
		t.Fatal("traffic clear acknowledgement bypassed", w.Code)
	}
	if w := call(`{"confirm":true}`); w.Code != 200 || manager.clears != 1 {
		t.Fatal("legitimate traffic clear failed", w.Code)
	}
}

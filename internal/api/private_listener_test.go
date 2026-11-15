package api

import (
	"context"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"net/http/httptest"
	"strings"
	"testing"
)

type privateSettings struct {
	testSettings
	last bool
}

func (s *privateSettings) Status(context.Context) (settings.Snapshot, error) {
	return settings.Snapshot{Revision: 2, Site: settings.Site{VPNLoopbackOnly: true}}, nil
}
func (s *privateSettings) Propose(_ context.Context, _ uint64, site settings.Site) error {
	s.proposals++
	s.last = site.VPNLoopbackOnly
	return nil
}
func TestOldPageCannotReopenPrivateListener(t *testing.T) {
	manager := &privateSettings{}
	origin := "https://example.com:8007"
	handler := (&Server{Auth: &testAuthentication{recent: true}, Settings: manager, Origins: map[string]bool{origin: true}}).Handler()
	call := func(body string) int {
		r := httptest.NewRequest("POST", "/api/settings/propose", strings.NewReader(body))
		r.Host = "example.com:8007"
		r.Header.Set("Origin", origin)
		r.Header.Set("Authorization", "Bearer fixture-session")
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	if code := call("{\"revision\":2,\"site\":{\"admin_port\":8006}}"); code != 400 || manager.proposals != 0 {
		t.Fatal("old page silently reopened private listener", code)
	}
	if code := call("{\"revision\":2,\"site\":{\"vpn_loopback_only\":true}}"); code != 200 || !manager.last {
		t.Fatal("explicit private intent lost", code)
	}
	if code := call("{\"revision\":2,\"site\":{\"vpn_loopback_only\":false}}"); code != 200 || manager.last {
		t.Fatal("explicit authorized reopen rejected", code)
	}
}

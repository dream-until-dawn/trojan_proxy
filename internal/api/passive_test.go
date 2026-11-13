package api

import (
	"net/http/httptest"
	"strings"
	"testing"
)

type passiveAuth struct {
	testAuthentication
	active, passive int
}

func (a *passiveAuth) ValidateAt(token, endpoint string, passive bool) bool {
	if passive {
		a.passive++
		return false
	}
	a.active++
	return true
}

func TestAutomaticLivePollingUsesPassiveAuthentication(t *testing.T) {
	auth := &passiveAuth{}
	origin := "https://example.com:8007"
	handler := (&Server{Auth: auth, Origins: map[string]bool{origin: true}, Traffic: &testTraffic{}}).Handler()
	r := httptest.NewRequest("POST", "/api/traffic/live", strings.NewReader("{}"))
	r.Host = "example.com:8007"
	r.Header.Set("Origin", origin)
	r.Header.Set("Authorization", "Bearer fixture-session")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 401 || auth.passive != 1 || auth.active != 0 {
		t.Fatal("automatic polling renewed active session", w.Code, auth.active, auth.passive)
	}
}

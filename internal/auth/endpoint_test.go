package auth

import (
	"strings"
	"testing"
	"time"
)

func TestWrongEntryAndPassiveRequestsNeverExtendSession(t *testing.T) {
	start := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	token := strings.Repeat("a", 43)
	for _, passive := range []bool{false, true} {
		service := NewService(nil, nil)
		now := start
		service.now = func() time.Time { return now }
		service.sessions[TokenHash(token)] = session{created: start, last: start, endpoint: "https://example.com/proxy"}
		now = start.Add(29 * time.Minute)
		if service.ValidateAt(token, "https://proxy.example.com", passive) {
			t.Fatal("wrong entry accepted")
		}
		if !service.ValidateAt(token, "https://example.com/proxy", true) {
			t.Fatal("valid passive session rejected")
		}
		now = start.Add(31 * time.Minute)
		if service.ValidateAt(token, "https://example.com/proxy", false) {
			t.Fatal("wrong entry or passive request extended idle expiry")
		}
	}
	service := NewService(nil, nil)
	if service.ValidateAt(token, "", false) {
		t.Fatal("empty entry accepted")
	}
	if _, err := service.LoginAt(nil, "", "", "", ""); err != ErrUnavailable {
		t.Fatal("empty login entry consumed credentials")
	}
}

package bootstrap

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalHTTPBoundaryAndCompleteFlow(t *testing.T) {
	s, _, token, now := fixture(t)
	completed := 0
	h := s.Handler(18092, func() { completed++ })
	call := func(path, origin, host, remote, forwarded, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Host = host
		r.RemoteAddr = remote
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		if forwarded != "" {
			r.Header.Set("X-Forwarded-For", forwarded)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body, _ := json.Marshal(map[string]string{"token": token, "password": "test-password-at-least-sixteen"})
	for _, bad := range []struct{ origin, host, remote, forwarded string }{
		{"http://evil.example", "127.0.0.1:18092", "127.0.0.1:1234", ""},
		{"http://127.0.0.1:18092", "evil.example", "127.0.0.1:1234", ""},
		{"https://qin-xin.top:8007", "qin-xin.top:8007", "127.0.0.1:1234", ""},
		{"http://127.0.0.1:18092", "127.0.0.1:18092", "192.0.2.1:1234", ""},
		{"http://127.0.0.1:18092", "127.0.0.1:18092", "127.0.0.1:1234", "192.0.2.1"},
		{"http://localhost:18092", "127.0.0.1:18092", "127.0.0.1:1234", ""},
	} {
		if w := call("/api/setup/begin", bad.origin, bad.host, bad.remote, bad.forwarded, string(body)); w.Code != 403 {
			t.Fatalf("unsafe request accepted: %+v %d", bad, w.Code)
		}
	}
	request := func(path, body string) *httptest.ResponseRecorder {
		return call(path, "http://127.0.0.1:18092", "127.0.0.1:18092", "127.0.0.1:1234", "", body)
	}
	for _, bad := range []string{string(body) + " {}", `{"unknown":1}`, strings.Repeat("x", 5000)} {
		if w := request("/api/setup/begin", bad); w.Code != 400 {
			t.Fatal("malformed request accepted", w.Code)
		}
	}
	w := request("/api/setup/begin", string(body))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("secret response headers unsafe")
	}
	var e Enrollment
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	finish, _ := json.Marshal(map[string]any{"session": e.Session, "otp": otp(e.Secret, now), "saved": true})
	if w = request("/api/setup/finish", string(finish)); w.Code != 200 || completed != 1 {
		t.Fatal("HTTP completion failed", w.Code, w.Body.String())
	}
	if w = request("/api/setup/finish", string(finish)); w.Code == 200 || completed != 1 {
		t.Fatal("HTTP completion replay accepted")
	}
}

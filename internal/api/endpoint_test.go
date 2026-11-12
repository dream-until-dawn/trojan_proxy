package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
	"github.com/dream-until-dawn/trojan_proxy/internal/webui"
)

func TestAdminPathSegmentBoundary(t *testing.T) {
	s := &Server{EndpointsProvider: func() []adminentry.Endpoint {
		return []adminentry.Endpoint{{Origin: "https://qin-xin.top", Prefix: "/proxy"}}
	}}
	handler := s.withEndpointPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	for _, target := range []string{"/proxy-other/", "/proxy2/api/status"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = "qin-xin.top"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Fatal("management prefix matched sibling path", target, w.Code)
		}
	}
}

// 验证真实前缀、资源及鉴权边界，不能让转发头扩展授权入口。
func TestAdminPathEndpointBoundary(t *testing.T) {
	entries := []adminentry.Endpoint{{Origin: "https://qin-xin.top", Prefix: "/proxy"}}
	handler := (&Server{Auth: &testAuthentication{}, Static: webui.Handler(), EndpointsProvider: func() []adminentry.Endpoint { return entries }}).Handler()
	cases := []struct {
		method, target, host, origin, token string
		code                                int
	}{
		{"GET", "/proxy?x=1", "qin-xin.top", "", "", 308},
		{"GET", "/proxy/", "qin-xin.top", "", "", 200},
		{"GET", "/proxy/main.js", "qin-xin.top", "", "", 200},
		{"GET", "/proxy/style.css", "qin-xin.top", "", "", 200},
		{"POST", "/proxy/api/status", "qin-xin.top", "https://qin-xin.top", "", 401},
		{"POST", "/proxy/api/status", "qin-xin.top", "https://qin-xin.top", "fixture-session", 200},
		{"POST", "/proxy/api/status", "qin-xin.top", "https://evil.test", "fixture-session", 403},
		{"POST", "/api/status", "qin-xin.top", "https://qin-xin.top", "fixture-session", 404},
		{"GET", "/proxy-other/", "qin-xin.top", "", "", 404},
		{"GET", "/proxy/../api/status", "qin-xin.top", "", "", 404},
		{"GET", "/proxy/%61pi/status", "qin-xin.top", "", "", 404},
		{"GET", "/proxy/", "evil.test", "", "", 421},
	}
	for _, c := range cases {
		t.Run(c.method+c.target+c.origin, func(t *testing.T) {
			r := httptest.NewRequest(c.method, c.target, nil)
			r.Host = c.host
			r.Header.Set("Origin", c.origin)
			r.Header.Set("Authorization", "Bearer "+c.token)
			r.Header.Set("X-Forwarded-Prefix", "/proxy")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != c.code {
				t.Fatalf("endpoint boundary %s: got %d want %d: %s", c.target, w.Code, c.code, w.Body.String())
			}
			if c.code == 308 && w.Header().Get("Location") != "/proxy/?x=1" {
				t.Fatal("canonical redirect lost prefix/query")
			}
			if c.target == "/proxy/" && c.code == 200 && !strings.Contains(w.Body.String(), `src="./main.js"`) {
				t.Fatal("assets are not relative to management entry")
			}
		})
	}
	entries = nil
	r := httptest.NewRequest("GET", "/proxy/", nil)
	r.Host = "qin-xin.top"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 421 {
		t.Fatal("revoked endpoint remained accessible", w.Code)
	}
}

package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
	"github.com/dream-until-dawn/trojan_proxy/internal/subscription"
)

func TestSubscriptionHTTPAuthorizationAndScope(t *testing.T) {
	ctx := context.Background()
	store, err := subscription.Open(ctx, filepath.Join(t.TempDir(), "subscription.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	owner := strings.Repeat("a", 64)
	manager := subscription.New(store, func(context.Context) (string, error) { return owner, nil }, func(context.Context) ([]byte, error) {
		return []byte(`{"proxies":[{"password":"profile-secret-sentinel"}],"rules":["MATCH,独用Trojan"]}`), nil
	})
	auth := &testAuthentication{}
	origin := "https://proxy.fixture.test"
	prefix := "/proxy"
	handler := (&Server{Auth: auth, Subscriptions: manager, EndpointsProvider: func() []adminentry.Endpoint { return []adminentry.Endpoint{{Origin: origin, Prefix: prefix}} }}).Handler()
	call := func(method, path, token, source, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, prefix+path, strings.NewReader(body))
		r.Host = "proxy.fixture.test"
		if source != "" {
			r.Header.Set("Origin", source)
		}
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := call("POST", "/api/subscriptions/create", "", origin, `{"name":"电脑"}`); w.Code != 401 {
		t.Fatal("unauthenticated creation accepted", w.Code)
	}
	if w := call("POST", "/api/subscriptions/create", "fixture-session", origin, `{"name":"电脑"}`); w.Code != 403 {
		t.Fatal("creation missing recent MFA accepted", w.Code)
	}
	auth.recent = true
	if w := call("POST", "/api/subscriptions/create", "fixture-session", "https://untrusted.invalid", `{"name":"电脑"}`); w.Code != 403 {
		t.Fatal("cross-origin creation accepted", w.Code)
	}
	created := call("POST", "/api/subscriptions/create", "fixture-session", origin, `{"name":"电脑"}`)
	if created.Code != 200 {
		t.Fatal("creation rejected", created.Code, created.Body.String())
	}
	var response struct {
		Item subscription.Record `json:"item"`
		URL  string              `json:"url"`
	}
	if err = json.Unmarshal(created.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(response.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "proxy.fixture.test" || parsed.Path != "/proxy/subscription/clash" {
		t.Fatal("subscription URL wrong entry", response.URL, err)
	}
	token := parsed.Query().Get("token")
	for _, query := range []string{"", "?token=invalid", "?token=" + token + "&token=" + token, "?token=" + token + "&url=https://untrusted.invalid", "?token=%zz"} {
		w := call("GET", "/subscription/clash"+query, "", "", "")
		if w.Code != 404 || strings.Contains(w.Body.String(), "profile-secret-sentinel") || strings.Contains(w.Body.String(), token) {
			t.Fatal("invalid subscription disclosed profile/token", w.Code)
		}
	}
	valid := call("GET", "/subscription/clash?token="+token, "", "", "")
	if valid.Code != 200 || !strings.Contains(valid.Body.String(), "profile-secret-sentinel") || valid.Header().Get("Cache-Control") != "no-store" || !strings.Contains(valid.Header().Get("Content-Type"), "yaml") {
		t.Fatal("valid URL fetch failed", valid.Code)
	}
	if w := call("GET", "/subscription/clash?token="+token, "", "https://untrusted.invalid", ""); w.Code != 403 {
		t.Fatal("cross-origin public fetch accepted", w.Code)
	}
	if w := call("POST", "/api/status", token, origin, `{}`); w.Code != 401 {
		t.Fatal("subscription token authorized administrator API", w.Code)
	}
	list := call("POST", "/api/subscriptions/list", "fixture-session", origin, `{}`)
	if list.Code != 200 || strings.Contains(list.Body.String(), token) || strings.Contains(list.Body.String(), "digest") || strings.Contains(list.Body.String(), "profile-secret-sentinel") {
		t.Fatal("metadata leaked subscription secret", list.Code)
	}
	auth.recent = false
	if w := call("POST", "/api/subscriptions/revoke", "fixture-session", origin, `{"id":"`+response.Item.ID+`"}`); w.Code != 403 {
		t.Fatal("revocation missing MFA accepted", w.Code)
	}
	auth.recent = true
	if w := call("POST", "/api/subscriptions/revoke", "fixture-session", origin, `{"id":"`+response.Item.ID+`"}`); w.Code != 200 {
		t.Fatal("revocation failed", w.Code)
	}
	if w := call("GET", "/subscription/clash?token="+token, "", "", ""); w.Code != 404 {
		t.Fatal("revoked subscription returned profile", w.Code)
	}
}

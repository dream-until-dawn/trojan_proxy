package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/webaccess"
)

type testWebAccess struct {
	reads, writes int
	err           error
}

func (s *testWebAccess) State() webaccess.State { return webaccess.State{Available: true} }
func (s *testWebAccess) Policy(context.Context) (webaccess.Policy, error) {
	return webaccess.Policy{Revision: 2, CIDRs: []string{"192.0.2.1/32"}}, s.err
}
func (s *testWebAccess) Dashboard(context.Context, webaccess.Filter) (webaccess.Dashboard, error) {
	s.reads++
	return webaccess.Dashboard{Rows: []webaccess.Record{{IP: "192.0.2.1", Path: "/private"}}}, s.err
}
func (s *testWebAccess) SetWhitelist(context.Context, uint64, []string) error {
	s.writes++
	return s.err
}
func TestWebAccessAuthenticationMFAAndValidation(t *testing.T) {
	auth := &testAuthentication{}
	manager := &testWebAccess{}
	origin := "https://example.com:8007"
	h := (&Server{Auth: auth, Origins: map[string]bool{origin: true}, WebAccess: manager}).Handler()
	call := func(path, token, source, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/access/"+path, strings.NewReader(body))
		r.Host = "example.com:8007"
		r.Header.Set("Origin", source)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"status", "policy", "dashboard", "policy/apply"} {
		if w := call(path, "", origin, `{"hours":24}`); w.Code != 401 || strings.Contains(w.Body.String(), "192.0.2.1") {
			t.Fatal("访问数据未认证泄露", w.Code)
		}
		if w := call(path, "fixture-session", "https://evil.test", `{}`); w.Code != 403 {
			t.Fatal("跨来源未拒绝", w.Code)
		}
	}
	if w := call("dashboard", "fixture-session", origin, `{"hours":24}`); w.Code != 200 || !strings.Contains(w.Body.String(), "/private") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("认证访问统计读取失败", w.Code)
	}
	for _, body := range []string{`{"hours":721}`, `{"hours":24,"trust":"bad"}`, `{"hours":24,"ip":"example.com"}`, `{"hours":24,"headers":true}`, `{} {}`} {
		if w := call("dashboard", "fixture-session", origin, body); w.Code != 400 {
			t.Fatal("无效查询到达访问库", w.Code)
		}
	}
	if manager.reads != 1 {
		t.Fatal("拒绝查询发生库读取")
	}
	valid := `{"revision":2,"cidrs":["192.0.2.1"],"confirm":true}`
	if w := call("policy/apply", "fixture-session", origin, valid); w.Code != 403 || manager.writes != 0 {
		t.Fatal("访问白名单绕过近期MFA", w.Code)
	}
	auth.recent = true
	for _, body := range []string{`{"revision":2,"cidrs":[],"confirm":false}`, `{"revision":2,"cidrs":["bad"],"confirm":true}`, `{"revision":0,"cidrs":[],"confirm":true}`} {
		if w := call("policy/apply", "fixture-session", origin, body); w.Code != 400 || manager.writes != 0 {
			t.Fatal("无效白名单被写入", w.Code)
		}
	}
	if w := call("policy/apply", "fixture-session", origin, valid); w.Code != 200 || manager.writes != 1 {
		t.Fatal("合法白名单修改失败", w.Code)
	}
	manager.err = webaccess.ErrRevision
	if w := call("policy/apply", "fixture-session", origin, valid); w.Code != 409 {
		t.Fatal("修订冲突未返回409", w.Code)
	}
	if w := call("dashboard", "fixture-session", origin, `{"hours":24}`); w.Code != 503 {
		t.Fatal("访问库故障被报告为成功", w.Code)
	}
}

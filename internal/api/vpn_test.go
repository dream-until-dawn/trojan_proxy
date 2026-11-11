package api

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/vpnservice"
)

type testVPN struct{ writes, exports int }

func (v *testVPN) Status(context.Context) (vpnservice.Status, error) {
	return vpnservice.Status{Enabled: true, Running: true}, nil
}
func (v *testVPN) Apply(context.Context, uint64, bool, bool) error { v.writes++; return nil }
func (v *testVPN) Export(context.Context) ([]byte, error) {
	v.exports++
	return []byte(`{"password":"fixture-vpn-secret"}`), nil
}

func TestVPNAPIRequiresAuthOriginAndRecentMFA(t *testing.T) {
	auth := &testAuthentication{}
	manager := &testVPN{}
	origin := "https://qin-xin.top:8007"
	handler := (&Server{Auth: auth, Origins: map[string]bool{origin: true}, VPN: manager}).Handler()
	call := func(path, token, source, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Host = "qin-xin.top:8007"
		r.Header.Set("Origin", source)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/api/vpn/status", "/api/vpn/apply", "/api/vpn/export"} {
		if w := call(path, "", origin, `{}`); w.Code != 401 {
			t.Fatal("VPN未认证访问未拒绝", path, w.Code)
		}
		if w := call(path, "fixture-session", "https://qin-xin.top:8008", `{}`); w.Code != 403 {
			t.Fatal("VPN跨来源访问未拒绝", path, w.Code)
		}
	}
	for _, path := range []string{"/api/vpn/apply", "/api/vpn/export"} {
		if w := call(path, "fixture-session", origin, `{"revision":1,"enabled":false}`); w.Code != 403 {
			t.Fatalf("VPN近期MFA未拒绝 %s: %d", path, w.Code)
		}
	}
	if manager.writes != 0 || manager.exports != 0 {
		t.Fatal("被拒绝的VPN操作仍执行")
	}
	if w := call("/api/vpn/status", "fixture-session", origin, `{}`); w.Code != 200 || strings.Contains(w.Body.String(), "fixture-vpn-secret") {
		t.Fatal("普通VPN状态泄漏秘密或要求重复MFA")
	}
	auth.recent = true
	if w := call("/api/vpn/apply", "fixture-session", origin, `{"revision":1,"enabled":false}`); w.Code != 200 || manager.writes != 1 {
		t.Fatal("合法VPN修改失败", w.Code)
	}
	if w := call("/api/vpn/export", "fixture-session", origin, `{}`); w.Code != 200 || manager.exports != 1 || !strings.Contains(w.Body.String(), "fixture-vpn-secret") || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("合法VPN下载失败或缺少秘密保护响应头", w.Code)
	}
	for _, body := range []string{`{"revision":1,"password":"arbitrary"}`, `{"enabled":false,"rotate":true}`, `{} {}`} {
		if w := call("/api/vpn/apply", "fixture-session", origin, body); w.Code != 400 {
			t.Fatal("任意密码或错误VPN命令未拒绝", w.Code)
		}
	}
	if manager.writes != 1 {
		t.Fatal("非法VPN请求造成额外写入")
	}
}

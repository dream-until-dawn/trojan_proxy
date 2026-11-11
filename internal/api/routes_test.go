package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	"github.com/dream-until-dawn/trojan_proxy/internal/routing"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

type testAuthentication struct{ recent bool }

func (a *testAuthentication) Login(context.Context, string, string, string) (string, error) {
	return "", errors.New("not used")
}
func (a *testAuthentication) Validate(token string) bool { return token == "fixture-session" }
func (a *testAuthentication) Recent(string) bool         { return a.recent }
func (a *testAuthentication) Logout(string)              {}

type routeEngine struct{ config string }

func (e *routeEngine) Check(context.Context, string) error         { return nil }
func (e *routeEngine) Apply(_ context.Context, value string) error { e.config = value; return nil }
func (e *routeEngine) Current(context.Context) (string, error)     { return e.config, nil }

func TestRouteAPIRecentMFAAndRevisions(t *testing.T) {
	ctx := context.Background()
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "routes.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	engine := &routeEngine{config: `{"apps":{}}`}
	settings := gateway.Settings{Domain: "qin-xin.top", AdminPort: 8007, ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443}}
	auth := &testAuthentication{}
	handler := (&Server{Auth: auth, Origins: map[string]bool{"https://qin-xin.top:8007": true}, Routes: routing.NewService(db, engine, settings)}).Handler()
	rule := routes.Rule{ID: "app", Name: "应用", Port: 18001, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3000}
	call := func(revision uint64, ruleset []routes.Rule, origin string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]any{"revision": revision, "rules": ruleset})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/api/routes/apply", strings.NewReader(string(body)))
		r.Host = "qin-xin.top:8007"
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer fixture-session")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := call(1, []routes.Rule{rule}, "https://qin-xin.top:8007"); w.Code != 403 {
		t.Fatalf("近期双因素保护未拒绝: %d", w.Code)
	}
	state, err := db.Load(ctx)
	if err != nil || state.Applied.Number != 1 || state.Pending != nil {
		t.Fatal("拒绝请求仍修改持久化状态", state, err)
	}
	auth.recent = true
	if w := call(1, []routes.Rule{rule}, "https://qin-xin.top:8007"); w.Code != 200 {
		t.Fatal("合法规则应用失败", w.Code, w.Body.String())
	}
	if w := call(1, nil, "https://qin-xin.top:8007"); w.Code != 409 {
		t.Fatal("过时修订未拒绝", w.Code, w.Body.String())
	}
	rule.Port = 8007
	if w := call(2, []routes.Rule{rule}, "https://qin-xin.top:8007"); w.Code != 400 || !strings.Contains(w.Body.String(), "端口") {
		t.Fatal("未返回可读的规则校验错误", w.Code, w.Body.String())
	}
	if w := call(2, nil, "https://qin-xin.top:8008"); w.Code != 403 {
		t.Fatal("跨来源写入未拒绝", w.Code)
	}
	state, err = db.Load(ctx)
	if err != nil || state.Applied.Number != 2 {
		t.Fatal("无效请求改变已提交修订", state, err)
	}
}

//go:build integration

package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
	"github.com/dream-until-dawn/trojan_proxy/internal/api"
	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"github.com/dream-until-dawn/trojan_proxy/internal/webui"
)

// testAdminPathLifecycle 在真实TLS网关后验证资源、真实认证、业务保留及旧监听关闭。
func testAdminPathLifecycle(t *testing.T, engine *gateway.Client, settings gateway.Settings) {
	ctx := context.Background()
	original, err := engine.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Apply(ctx, original); err != nil {
			t.Error(err)
		}
	}()
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "admin.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	hash, err := auth.HashPassword("fixture-strong-password-123")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := auth.EncryptSecret(make([]byte, 32), secret)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CreateAccount(ctx, storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: -1, Recovery: []string{auth.TokenHash("fixture-recovery")}}); err != nil {
		t.Fatal(err)
	}
	service := auth.NewService(db, make([]byte, 32))
	settings.Domain = "localhost.test"
	settings.Policy.AllowStandardPorts = true
	settings.Ingress = &gateway.Ingress{Mode: "manual", Certificate: "/certificates/test/fullchain.cer", Key: "/certificates/test/private.key"}
	// 动态入口在生产由同一份数据库快照决定；这里显式模拟确认前后两种状态。
	entries := []adminentry.Endpoint{adminentry.ForSite(settings.Domain, settings.AdminPort, settings.ControlPort, ""), {Origin: "https://localhost.test", Prefix: "/proxy"}}
	var allowed atomic.Value
	allowed.Store(entries)
	handler := (&api.Server{Auth: service, Static: webui.Handler(), EndpointsProvider: func() []adminentry.Endpoint { return allowed.Load().([]adminentry.Endpoint) }}).Handler()
	management := httptest.NewServer(handler)
	defer management.Close()
	_, number, _ := net.SplitHostPort(management.Listener.Addr().String())
	settings.ControlPort, _ = strconv.Atoi(number)
	settings.Policy.ControlPort = settings.ControlPort
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "business:"+r.RequestURI) }))
	defer backend.Close()
	_, number, _ = net.SplitHostPort(backend.Listener.Addr().String())
	businessPort, _ := strconv.Atoi(number)
	ruleset := []routes.Rule{{ID: "futures", Name: "期货", Port: 443, Host: settings.Domain, Path: "/futures", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: businessPort, HTTPS: true}}
	candidate := settings
	candidate.AdminPath = "/proxy"
	body, err := gateway.CompileAdminTransition(settings, candidate, ruleset)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(ctx, body); err != nil {
		t.Fatal("real path transition rejected", err)
	}
	pem, err := os.ReadFile("/certs/fullchain.cer")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: settings.Domain, RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		_, p, _ := net.SplitHostPort(address)
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", p))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, target, origin, token, payload string) (int, string, http.Header) {
		t.Helper()
		r, _ := http.NewRequest(method, target, strings.NewReader(payload))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(r)
		if err != nil {
			t.Fatal(target, err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(data), resp.Header
	}
	root := "https://localhost.test"
	legacy := root + ":" + strconv.Itoa(settings.AdminPort)
	if code, _, _ := call("GET", legacy+"/", "", "", ""); code != 200 {
		t.Fatal("old entry unavailable during migration", code)
	}
	if code, _, headers := call("GET", root+"/proxy?keep=1", "", "", ""); code != 308 || headers.Get("Location") != "/proxy/?keep=1" {
		t.Fatal("canonical path redirect broken", code, headers)
	}
	for _, p := range []string{"/proxy/", "/proxy/main.js", "/proxy/auth.js", "/proxy/style.css"} {
		if code, _, _ := call("GET", root+p, "", "", ""); code != 200 {
			t.Fatal("prefixed asset unavailable", p, code)
		}
	}
	if code, _, _ := call("POST", root+"/proxy/api/status", root, "", ""); code != 401 {
		t.Fatal("unauthenticated path API accepted", code)
	}
	if code, _, _ := call("POST", root+"/proxy/api/login", root, "", `{"password":"wrong","recovery":"fixture-recovery"}`); code != 401 {
		t.Fatal("wrong login accepted", code)
	}
	code, data, _ := call("POST", root+"/proxy/api/login", root, "", `{"password":"fixture-strong-password-123","recovery":"fixture-recovery"}`)
	var login map[string]string
	if err = json.Unmarshal([]byte(data), &login); err != nil || code != 200 || login["token"] == "" {
		t.Fatal("real prefixed login failed", code, data, err)
	}
	token := login["token"]
	if code, _, _ := call("POST", root+"/proxy/api/status", root, token, ""); code != 200 {
		t.Fatal("authenticated path API failed", code)
	}
	if code, _, _ := call("POST", root+"/proxy/api/status", "https://evil.test", token, ""); code != 403 {
		t.Fatal("cross-origin path API accepted", code)
	}
	if code, data, _ := call("GET", root+"/futures/login?x=1", "", "", ""); code != 200 || data != "business:/futures/login?x=1" {
		t.Fatal("path migration changed futures", code, data)
	}
	if code, data, _ := call("GET", root+"/proxy-other", "", "", ""); code != 200 || strings.Contains(data, "./main.js") {
		t.Fatal("management matched sibling path", code, data)
	}
	body, err = gateway.Compile(candidate, ruleset)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(ctx, body); err != nil {
		t.Fatal(err)
	}
	// 先通过受信任API完成确认，网关移除监听后才撤回旧入口授权。
	entries = entries[1:]
	allowed.Store(entries)
	if code, _, _ := call("POST", root+"/proxy/api/status", root, token, ""); code != 200 {
		t.Fatal("confirmed path unavailable", code)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(settings.AdminPort)))
	if err != nil {
		t.Fatal("confirmed path retained old listener", err)
	}
	listener.Close()
}

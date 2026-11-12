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
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/files"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	"github.com/dream-until-dawn/trojan_proxy/internal/routing"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func port(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func fetch(t *testing.T, port int, path string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return r.StatusCode, string(body)
}

func TestRealGatewayLifecycle(t *testing.T) {
	ctx := context.Background()
	engine := gateway.NewClient("/run/caddy/admin.sock")
	var settings gateway.Settings
	var backendPort int
	first := os.Getenv("TROJAN_GATEWAY_PHASE") == "first"
	if first {
		settings = gateway.Settings{Domain: "localhost", AdminPort: port(t), ControlPort: port(t), FilePort: port(t), Socket: "/run/caddy/admin.sock"}
		backendPort = port(t)
		settings.Policy = routes.Policy{AdminPort: settings.AdminPort, ControlPort: settings.ControlPort, FilePort: settings.FilePort, VPNPort: 18443, Directories: map[string]string{"demo": "/public/demo"}}
	} else {
		body, err := os.ReadFile("/state/settings.json")
		if err != nil {
			t.Fatal(err)
		}
		var saved struct {
			Settings    gateway.Settings
			BackendPort int
		}
		if err = json.Unmarshal(body, &saved); err != nil {
			t.Fatal(err)
		}
		settings, backendPort = saved.Settings, saved.BackendPort
	}
	backendListener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(backendPort))
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "all")
		if strings.HasSuffix(r.URL.Path, "/business-missing") {
			w.WriteHeader(404)
		}
		io.WriteString(w, "upstream:"+r.URL.Path)
	}))
	backend.Listener = backendListener
	backend.Start()
	defer backend.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err = engine.Current(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("非root进程无法访问网关Unix socket", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if first {
		baseline, err := gateway.Compile(settings, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = engine.Apply(ctx, baseline); err != nil {
			t.Fatal("基线配置应用失败", err)
		}
	}
	store, err := storage.OpenJournal(ctx, "/state/state.db", control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := routing.NewService(store, engine, settings)
	if first {
		if err = os.MkdirAll("/public/demo", 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile("/public/demo/report.txt", []byte("file-sentinel"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := files.OpenRoot("/public/demo")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fileListener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(settings.FilePort))
	if err != nil {
		t.Fatal(err)
	}
	fileServer := httptest.NewUnstartedServer(&files.Handler{Roots: map[string]*files.Root{"demo": root}, Resolver: service})
	fileServer.Listener = fileListener
	fileServer.Start()
	defer fileServer.Close()
	var ruleset []routes.Rule
	if first {
		publicPort := port(t)
		ruleset = []routes.Rule{{ID: "app", Name: "应用", Port: publicPort, Path: "/app", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: backendPort, StripPrefix: true},
			{ID: "files_rule", Name: "下载", Port: publicPort, Path: "/downloads", Kind: "files", DirectoryID: "demo", Browse: true}}
		if err = service.Apply(ctx, 1, ruleset); err != nil {
			t.Fatal("真实规则未生效", err)
		}
		occupied, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		bad := append([]routes.Rule(nil), ruleset...)
		bad = append(bad, routes.Rule{ID: "conflict", Name: "故意占用", Port: occupied.Addr().(*net.TCPAddr).Port, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: backendPort})
		if err = service.Apply(ctx, 2, bad); err == nil {
			t.Fatal("端口冲突未拒绝")
		}
		state, err := service.List(ctx)
		if err != nil || state.Revision != 2 || state.Pending || len(state.Rules) != 2 {
			t.Fatal("冲突后实际修订不一致", state, err)
		}
		body, err := json.Marshal(struct {
			Settings    gateway.Settings
			BackendPort int
		}{settings, backendPort})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile("/state/settings.json", body, 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		if err = service.Reconcile(ctx); err != nil {
			t.Fatal("实际网关重启后恢复失败", err)
		}
		state, err := service.List(ctx)
		if err != nil || state.Revision != 2 {
			t.Fatal("持久化修订未恢复", state, err)
		}
		ruleset = state.Rules
	}
	publicPort := ruleset[0].Port
	if status, body := fetch(t, publicPort, "/app/hello"); status != 200 || body != "upstream:/hello" {
		t.Fatal("实际反代或前缀剥离错误", status, body)
	}
	if status, _ := fetch(t, publicPort, "/apple/hello"); status != 404 {
		t.Fatal("路径边界匹配错误", status)
	}
	if status, body := fetch(t, publicPort, "/downloads/report.txt"); status != 200 || body != "file-sentinel" {
		t.Fatal("实际目录下载失败", status, body)
	}
	if status, body := fetch(t, publicPort, "/downloads/"); status != 200 || !strings.Contains(body, `href="./report.txt"`) {
		t.Fatal("实际索引链接错误", status, body)
	}
	if status, _ := fetch(t, publicPort, "/downloads"); status != 301 {
		t.Fatal("目录标准化跳转失败", status)
	}
	testRejectTLSReservation(t, engine, settings)
	testInternalKeepalive(t, engine, settings)
	t.Run("custom-https-origin-post-cookie-stream", func(t *testing.T) { testCustomHTTPS(t, engine, settings) })
	t.Run("prefix-preserve-strip-and-response-boundaries", func(t *testing.T) { testPrefixRoutingContract(t, engine, settings) })
	t.Run("admin-path-real-auth-assets-and-legacy-close", func(t *testing.T) { testAdminPathLifecycle(t, engine, settings) })
	testStandardIngress(t, engine, settings, backendPort)
	testAdminEntryTransition(t, engine, settings, ruleset)
	testLegacySettingsMigration(t, engine, settings, backendPort)
}

func testLegacySettingsMigration(t *testing.T, engine *gateway.Client, settings gateway.Settings, backendPort int) {
	t.Helper()
	ctx := context.Background()
	original, err := engine.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Apply(ctx, original); err != nil {
			t.Error("迁移探针后恢复失败", err)
		}
	}()
	rule := routes.Rule{ID: "migrate", Name: "迁移哨兵", Port: port(t), Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: backendPort}
	body, err := gateway.Compile(settings, []routes.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err = json.Unmarshal([]byte(body), &legacy); err != nil {
		t.Fatal(err)
	}
	for _, server := range legacy["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any) {
		delete(server.(map[string]any), "protocols")
	}
	oldJSON, _ := json.Marshal(legacy)
	rulesJSON, _ := json.Marshal([]routes.Rule{rule})
	if err = engine.Apply(ctx, string(oldJSON)); err != nil {
		t.Fatal(err)
	}
	store, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "migration.db"), control.Revision{Number: 1, Gateway: string(oldJSON), Rules: string(rulesJSON)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	state, err := routing.NewService(store, engine, settings).List(ctx)
	if err != nil || state.Revision != 2 {
		t.Fatal("真实旧配置安全策略迁移失败", state, err)
	}
	actual, err := engine.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var migrated map[string]any
	if err = json.Unmarshal([]byte(actual), &migrated); err != nil {
		t.Fatal(err)
	}
	for _, server := range migrated["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any) {
		protocols, _ := json.Marshal(server.(map[string]any)["protocols"])
		if string(protocols) != `["h1","h2"]` {
			t.Fatal("实际迁移配置仍开放其他协议", string(protocols))
		}
	}
	if status, body := fetch(t, rule.Port, "/migrated"); status != 200 || body != "upstream:/migrated" {
		t.Fatal("迁移破坏实际路由", status, body)
	}
	if state, err = routing.NewService(store, engine, settings).List(ctx); err != nil || state.Revision != 2 {
		t.Fatal("真实迁移重复提交", state, err)
	}
}

func testStandardIngress(t *testing.T, engine *gateway.Client, settings gateway.Settings, backendPort int) {
	t.Helper()
	ctx := context.Background()
	original, err := engine.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Apply(ctx, original); err != nil {
			t.Error("标准入口测试后恢复失败", err)
		}
	}()
	s := settings
	s.Domain = ""
	s.Policy.AllowStandardPorts = true
	s.Ingress = &gateway.Ingress{Mode: "reserved"}
	ruleset := []routes.Rule{{ID: "standard", Name: "标准入口", Port: 80, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: backendPort}}
	apply := func() {
		t.Helper()
		body, err := gateway.Compile(s, ruleset)
		if err != nil {
			t.Fatal(err)
		}
		if err = engine.Apply(ctx, body); err != nil {
			t.Fatal("标准入口配置被真实Caddy拒绝", err)
		}
	}
	apply()
	if status, body := fetch(t, 80, "/plain"); status != 200 || body != "upstream:/plain" {
		t.Fatal("无域名HTTP未承载服务", status, body)
	}
	if status, body := fetch(t, 80, "/robots.txt"); status != 200 || body != "User-agent: *\nDisallow: /\n" {
		t.Fatal("robots did not override root proxy", status, body)
	}
	ruleset[0].Path = "/app"
	apply()
	if status, body := fetch(t, 80, "/"); status != 200 || !strings.Contains(body, "<h1>欢迎访问</h1>") {
		t.Fatal("HTTP welcome fallback missing", status, body)
	}
	ruleset[0].Path = "/"
	apply()
	for _, address := range []string{"127.0.0.1:80", "127.0.0.1:443", "[::1]:80", "[::1]:443"} {
		if l, err := net.Listen("tcp", address); err == nil {
			l.Close()
			t.Fatal("标准入口未保留双栈端口", address)
		}
	}
	if l, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(s.AdminPort)); err != nil {
		t.Fatal("无域名模式仍开放公网后台端口", err)
	} else {
		l.Close()
	}
	if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:443", &tls.Config{ServerName: "localhost"}); err == nil {
		conn.Close()
		t.Fatal("无域名443意外提供TLS")
	}
	s.Domain = "localhost.test"
	s.Ingress = &gateway.Ingress{Mode: "manual", Certificate: "/certificates/test/fullchain.cer", Key: "/certificates/test/private.key"}
	apply()
	cert, err := os.ReadFile("/certs/fullchain.cer")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost.test"}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(scheme, host, target string) (int, string, string) {
		t.Helper()
		req, err := http.NewRequest("GET", scheme+"://127.0.0.1"+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(body), response.Header.Get("Location")
	}
	if status, _, location := request("http", s.Domain, "/safe?q=1"); status != 308 || location != "https://localhost.test/safe?q=1" {
		t.Fatal("80跳转丢失目标或未升级HTTPS", status, location)
	}
	if status, body, _ := request("https", s.Domain, "/secure"); status != 200 || body != "upstream:/secure" {
		t.Fatal("标准HTTPS业务失败", status, body)
	}
	for _, scheme := range []string{"http", "https"} {
		if status, _, location := request(scheme, "attacker.test", "/"); status != 404 || location != "" {
			t.Fatal("未授权Host被接受或用于跳转", scheme, status, location)
		}
	}
	ruleset[0].Path = "/app"
	apply()
	if status, body, _ := request("https", s.Domain, "/"); status != 200 || !strings.Contains(body, "欢迎访问 localhost.test") || strings.Contains(body, "Trojan") {
		t.Fatal("HTTPS welcome fallback invalid", status, body)
	}
	if status, body, _ := request("https", s.Domain, "/app/business-missing"); status != 404 || body != "upstream:/app/business-missing" {
		t.Fatal("welcome swallowed business 404", status, body)
	}
	for _, scheme := range []string{"http", "https"} {
		if status, body, location := request(scheme, s.Domain, "/robots.txt"); status != 200 || body != "User-agent: *\nDisallow: /\n" || location != "" {
			t.Fatal("standard-port robots declaration invalid", scheme, status, body, location)
		}
	}
	req, _ := http.NewRequest("GET", "https://127.0.0.1/app/headers", nil)
	req.Host = s.Domain
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.Header.Get("X-Robots-Tag") != "noindex, nofollow, noarchive, nosnippet" {
		t.Fatal("upstream overrode crawl declaration", response.Header.Get("X-Robots-Tag"))
	}
	s.Ingress = &gateway.Ingress{Mode: "unavailable"}
	apply()
	if status, body, location := request("http", s.Domain, "/"); status != 200 || !strings.Contains(body, "#c64545") || location != "" {
		t.Fatal("unavailable certificate did not retain private HTTP fallback", status, body, location)
	}
	if status, body, _ := request("http", s.Domain, "/app"); status != 200 || body != "upstream:/app" {
		t.Fatal("unavailable certificate lost HTTP business", status, body)
	}
	if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:443", &tls.Config{RootCAs: roots, ServerName: s.Domain}); err == nil {
		conn.Close()
		t.Fatal("unavailable certificate accepted TLS")
	}
	if listener, err := net.Listen("tcp4", "0.0.0.0:443"); err == nil {
		listener.Close()
		t.Fatal("unavailable certificate released reserved HTTPS port")
	}
}

func testRejectTLSReservation(t *testing.T, engine *gateway.Client, settings gateway.Settings) {
	t.Helper()
	ctx := context.Background()
	certificate, err := os.ReadFile("/certs/fullchain.cer")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("测试信任根无效")
	}
	handshake := func() error {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(settings.AdminPort), &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS12})
		if conn != nil {
			conn.Close()
		}
		return err
	}
	if err = handshake(); err != nil {
		t.Fatal("拒绝策略前TLS基线失败", err)
	}
	original, err := engine.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var modified map[string]any
	if err = json.Unmarshal([]byte(original), &modified); err != nil {
		t.Fatal(err)
	}
	servers := modified["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	servers["admin"].(map[string]any)["tls_connection_policies"] = []any{map[string]any{"drop": true}}
	body, err := json.Marshal(modified)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(ctx, string(body)); err != nil {
		t.Fatal("网关不支持固定版本TLS拒绝策略", err)
	}
	if err = handshake(); err == nil {
		t.Fatal("存在可信证书时拒绝策略没有生效")
	}
	// 去掉所有证书引用后仍必须保留端口，验证HTTP-only部署无需伪造HTTPS。
	reserved := map[string]any{"admin": map[string]any{"listen": "unix/" + settings.Socket + "|0660"}, "apps": map[string]any{"tls": map[string]any{}, "http": map[string]any{"servers": map[string]any{"reserved": map[string]any{"listen": []string{":" + strconv.Itoa(settings.AdminPort)}, "automatic_https": map[string]any{"disable": true}, "protocols": []string{"h1", "h2"}, "tls_connection_policies": []any{map[string]any{"drop": true}}}}}}}
	body, err = json.Marshal(reserved)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(ctx, string(body)); err != nil {
		t.Fatal("无证书保留配置失败", err)
	}
	if listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(settings.AdminPort)); err == nil {
		listener.Close()
		t.Fatal("拒绝模式没有持有端口")
	}
	if err = handshake(); err == nil {
		t.Fatal("无证书模式错误提供TLS业务")
	}
	if err = engine.Apply(ctx, original); err != nil {
		t.Fatal("从拒绝模式恢复失败", err)
	}
	if err = handshake(); err != nil {
		t.Fatal("恢复后可信TLS失败", err)
	}
}

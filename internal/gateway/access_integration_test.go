//go:build integration

package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
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

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	"github.com/dream-until-dawn/trojan_proxy/internal/webaccess"
)

// TestRealAccessLogs 使用正式编译器与实际Caddy，检查写盘前脱敏而非仅检查入库结果。
func TestRealAccessLogs(t *testing.T) {
	ctx := context.Background()
	engine := gateway.NewClient("/run/caddy/admin.sock")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, e := engine.Current(ctx); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("网关未就绪")
		}
		time.Sleep(100 * time.Millisecond)
	}
	secret := "synthetic-access-secret-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	seen := make(chan string, 10)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		seen <- r.URL.Path
		w.Header().Set("Set-Cookie", "fixture="+secret)
		io.WriteString(w, "fixture-ok")
	}))
	defer backend.Close()
	admin := httptest.NewServer(backend.Config.Handler)
	defer admin.Close()
	_, adminNumber, _ := net.SplitHostPort(admin.Listener.Addr().String())
	controlPort, _ := strconv.Atoi(adminNumber)
	_, p, _ := net.SplitHostPort(backend.Listener.Addr().String())
	upstream, _ := strconv.Atoi(p)
	plain, secure := port(t), port(t)
	settings := gateway.Settings{Domain: "localhost.test", AdminPath: "/proxy", AdminPort: port(t), ControlPort: controlPort, FilePort: port(t), Socket: "/run/caddy/admin.sock", AccessLog: true,
		Policy: routes.Policy{AllowStandardPorts: true, VPNPort: 18443}, Ingress: &gateway.Ingress{Mode: "manual", Certificate: "/certificates/test/fullchain.cer", Key: "/certificates/test/private.key"}}
	settings.Policy.AdminPort = settings.AdminPort
	settings.Policy.ControlPort = controlPort
	settings.Policy.FilePort = settings.FilePort
	rules := []routes.Rule{{ID: "plain", Name: "测试前缀", Port: plain, Path: "/original", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: upstream, StripPrefix: true},
		{ID: "secure", Name: "测试错误", Port: secure, Host: settings.Domain, Path: "/error", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: port(t), HTTPS: true}}
	body, e := gateway.Compile(settings, rules)
	if e != nil {
		t.Fatal(e)
	}
	var config map[string]any
	json.Unmarshal([]byte(body), &config)
	// 仅将整点轮转加速为下一分钟；interval本身依赖新写入，不能证明空闲清理。
	writer := config["logging"].(map[string]any)["logs"].(map[string]any)["web_access"].(map[string]any)["writer"].(map[string]any)
	writer["roll_minutes"] = []int{time.Now().Add(time.Minute).Minute()}
	encoded, _ := json.Marshal(config)
	if e = engine.Apply(ctx, string(encoded)); e != nil {
		t.Fatal("日志配置被实际网关拒绝", e)
	}
	cert, e := os.ReadFile("/certs/fullchain.cer")
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	call := func(scheme string, port int, path string, want int) {
		t.Helper()
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: settings.Domain, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", port))
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		r, _ := http.NewRequest("POST", fmt.Sprintf("%s://%s:%d%s?token=%s", scheme, settings.Domain, port, path, secret), strings.NewReader(secret))
		r.Header.Set("Authorization", secret)
		r.Header.Set("Cookie", "fixture="+secret)
		r.Header.Set("X-Forwarded-For", "198.51.100.99")
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != want {
			t.Fatal("访问状态不符", path, response.StatusCode, want)
		}
	}
	call("http", 80, "/redirect", 308)
	call("http", 80, "/robots.txt", 200)
	call("https", 443, "/", 200)
	call("https", 443, "/proxy/test", 200)
	call("http", plain, "/original/first", 200)
	call("https", secure, "/error", 502)
	call("http", plain, "/missing", 404)
	// 时间轮转必须在没有新请求时发生，低流量也不能保留旧活动文件。
	time.Sleep(time.Until(time.Now().Truncate(time.Minute).Add(time.Minute).Add(500 * time.Millisecond)))
	entries, e := os.ReadDir("/data/access")
	if e != nil {
		t.Fatal(e)
	}
	var all []byte
	var files int
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".log") {
			b, e := os.ReadFile(filepath.Join("/data/access", entry.Name()))
			if e != nil {
				t.Fatal(e)
			}
			all = append(all, b...)
			files++
		}
	}
	if files < 2 {
		t.Fatal("空闲时未按时间轮转")
	}
	if strings.Contains(string(all), secret) || strings.Contains(string(all), "198.51.100.99") || strings.Contains(string(all), `"headers"`) || strings.Contains(string(all), `"resp_headers"`) {
		t.Fatal("落盘前隐私过滤失效")
	}
	lines := strings.Split(strings.TrimSpace(string(all)), "\n")
	if len(lines) != 7 {
		t.Fatal("HTTP请求漏记或重复", len(lines))
	}
	paths := map[string]bool{}
	ports := map[int]bool{}
	store, e := webaccess.Open(ctx, "/state/access.db")
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	for _, line := range lines {
		r, e := webaccess.Parse([]byte(line), time.Now())
		if e != nil {
			t.Fatal(e)
		}
		paths[r.Path] = true
		ports[r.Port] = true
		if r.IP != "127.0.0.1" {
			t.Fatal("来源不是实际连接IP", r.IP)
		}
	}
	if !paths["/original/first"] || paths["/first"] || !paths["/proxy/test"] || len(ports) != 4 {
		t.Fatal("原始路径或入口日志错误", paths, ports)
	}
	if _, e = store.Collect(ctx, "/data/access", time.Now()); e != nil {
		t.Fatal(e)
	}
	d, e := store.Dashboard(ctx, webaccess.Filter{Hours: 24}, time.Now())
	if e != nil || d.Totals.Requests != 7 || d.Totals.Errors != 2 {
		t.Fatal("实际日志入库统计不符", d, e)
	}
	close(seen)
	rewritten := false
	for path := range seen {
		if path == "/first" {
			rewritten = true
		}
	}
	if !rewritten {
		t.Fatal("夹具没有实际触发前缀重写")
	}
}

//go:build integration

package gateway_test

import (
	"context"
	"crypto/sha256"
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
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

func sharedFixture(t *testing.T) gateway.Settings {
	t.Helper()
	root := "/certificates/" + strings.Repeat("a", 64) + "/"
	return gateway.Settings{Domain: "vpn.test", AdminPort: 8007, ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", AccessLog: true,
		Ingress: &gateway.Ingress{Mode: "manual", Certificate: root + "fullchain.pem", Key: root + "private.key"}, SharedTrojan: &gateway.SharedTrojan{Port: 18443},
		Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443, AllowStandardPorts: true}}
}
func sharedRules() []routes.Rule {
	return []routes.Rule{{ID: "websocket", Name: "fixture", Port: 443, Host: "vpn.test", Path: "/ws", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 18080, HTTPS: true}}
}
func TestWriteSharedGatewayFixture(t *testing.T) {
	s := sharedFixture(t)
	body, e := gateway.Compile(s, sharedRules())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("/fixture/gateway.json", []byte(body), 0644); e != nil {
		t.Fatal(e)
	}
}

func TestRealShared443WebAndRollback(t *testing.T) {
	ctx := context.Background()
	s := sharedFixture(t)
	engine := gateway.NewClient(s.Socket)
	cert, e := os.ReadFile("/fixture/trusted.crt")
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(cert)
	config := &tls.Config{RootCAs: roots, ServerName: "vpn.test", MinVersion: tls.VersionTLS12}
	connect := func() net.Conn {
		t.Helper()
		c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}, "tcp", "127.0.0.1:443", config)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))
		return c
	}
	c := connect()
	// 总长小于58字节的合法HTTP请求不能被分类器拖住。
	c.Write([]byte("GET / HTTP/1.0\r\nHost: vpn.test\r\n\r\n"))
	body, e := io.ReadAll(c)
	c.Close()
	if e != nil || !strings.Contains(string(body), "200 OK") || !strings.Contains(string(body), "欢迎访问") {
		t.Fatal("short HTTP fallback failed", e)
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: config, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: time.Second}).DialContext(ctx, network, "127.0.0.1:443")
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "https://vpn.test/?token=shared-secret-sentinel", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.200")
	req.Header.Set("Authorization", "Bearer shared-header-sentinel")
	r, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r.ProtoMajor != 2 || r.StatusCode != 200 || r.Header.Get("X-Robots-Tag") == "" {
		t.Fatal("shared h2/TLS/fallback policy lost", r.Proto, r.StatusCode)
	}
	r, e = client.Get("https://vpn.test/robots.txt")
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if !strings.Contains(string(b), "Disallow: /") {
		t.Fatal("shared robots policy lost")
	}
	listener, e := net.Listen("tcp", "127.0.0.1:18080")
	if e != nil {
		t.Fatal(e)
	}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveFixtureWebSocket(w, r, "shared") }))
	backend.Listener = listener
	backend.Start()
	defer backend.Close()
	checkHostWebSocket(t, roots, "vpn.test", "shared")
	// 正向对照与负向SNI对照都穿过真实双层TLS；不能只检查配置里有没有verify字段。
	tunnel := func() bool {
		c := connect()
		defer c.Close()
		hash := sha256.Sum224([]byte("fixture-only-password-0123456789abcdef"))
		fmt.Fprintf(c, "%x\r\n", hash)
		c.Write([]byte{1, 1, 198, 51, 100, 20, 31, 64, 13, 10}) // CONNECT 198.51.100.20:8000。
		c.Write([]byte("GET / HTTP/1.0\r\nHost: public.test\r\n\r\n"))
		b, _ := io.ReadAll(c)
		return strings.Contains(string(b), "public-sentinel")
	}
	if !tunnel() {
		t.Fatal("shared backend TLS positive control failed")
	}
	current, e := engine.Current(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var badConfig map[string]any
	if e = json.Unmarshal([]byte(current), &badConfig); e != nil {
		t.Fatal(e)
	}
	public := badConfig["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["public_443"].(map[string]any)
	wrapper := public["listener_wrappers"].([]any)[0].(map[string]any)
	handles := wrapper["routes"].([]any)[0].(map[string]any)["handle"].([]any)
	branch := handles[1].(map[string]any)["routes"].([]any)[0].(map[string]any)
	upstream := branch["handle"].([]any)[0].(map[string]any)["upstreams"].([]any)[0].(map[string]any)
	upstream["tls"].(map[string]any)["server_name"] = "wrong.test"
	if os.Getenv("TROJAN_SHARED_TLS_MUTATION") == "1" {
		upstream["tls"].(map[string]any)["insecure_skip_verify"] = true
	}
	badBody, _ := json.Marshal(badConfig)
	if e = engine.Apply(ctx, string(badBody)); e != nil {
		t.Fatal(e)
	}
	if tunnel() {
		t.Fatal("backend wrong SNI still served target")
	}
	if e = engine.Apply(ctx, current); e != nil {
		t.Fatal(e)
	}
	bad := config.Clone()
	bad.ServerName = "unknown.test"
	// 仅此负向客户端跳过证书校验，证明是服务端拒绝未知SNI，而非客户端恰好拒绝错误证书。
	bad.InsecureSkipVerify = true
	if conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:443", bad); e == nil {
		conn.Close()
		t.Fatal("unknown SNI accepted")
	}
	v6, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "[::1]:443", config)
	if e != nil {
		t.Fatal("IPv6 shared ingress unavailable", e)
	}
	v6.SetDeadline(time.Now().Add(3 * time.Second))
	v6.Write([]byte("GET /robots.txt HTTP/1.0\r\nHost: vpn.test\r\n\r\n"))
	v6Body, e := io.ReadAll(v6)
	v6.Close()
	if e != nil || !strings.Contains(string(v6Body), "Disallow: /") {
		t.Fatal("IPv6 shared HTTP fallback failed", e)
	}
	// 不完整的十六进制前缀必须有界关闭，而非永久占用连接。
	slow := connect()
	start := time.Now()
	slow.Write([]byte("a"))
	buf := make([]byte, 1)
	_, e = slow.Read(buf)
	slow.Close()
	if e == nil || time.Since(start) > 4500*time.Millisecond {
		t.Fatal("shared incomplete prefix not bounded", e, time.Since(start))
	}
	var logs []byte
	deadline := time.Now().Add(time.Second * 2)
	for {
		logs = nil
		entries, _ := os.ReadDir("/data/access")
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".log") {
				b, _ := os.ReadFile(filepath.Join("/data/access", entry.Name()))
				logs = append(logs, b...)
			}
		}
		if strings.Contains(string(logs), "/robots.txt") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shared access logs missing")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(string(logs), "127.0.0.2") || strings.Contains(string(logs), "shared-secret-sentinel") || strings.Contains(string(logs), "shared-header-sentinel") || strings.Contains(string(logs), "203.0.113.200") {
		t.Fatal("shared source/log privacy violated")
	}
	s.SharedTrojan = nil
	off, e := gateway.Compile(s, sharedRules())
	if e != nil {
		t.Fatal(e)
	}
	if e = engine.Apply(ctx, off); e != nil {
		t.Fatal(e)
	}
	checkHostWebSocket(t, roots, "vpn.test", "shared")
	s.SharedTrojan = &gateway.SharedTrojan{Port: 18443}
	on, e := gateway.Compile(s, sharedRules())
	if e != nil {
		t.Fatal(e)
	}
	if e = engine.Apply(ctx, on); e != nil {
		t.Fatal(e)
	}
	actual, e := engine.Current(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var expected any
	json.Unmarshal([]byte(on), &expected)
	var actualValue any
	if e = json.Unmarshal([]byte(actual), &actualValue); e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(actualValue)
	b, _ = json.Marshal(expected)
	if string(a) != string(b) {
		t.Fatal("shared rollback/reapply configuration mismatch")
	}
	t.Log("shared443 short HTTP, h2, welcome, WS, source IP, log privacy, unknown SNI, bounded prefix and rollback passed")
}

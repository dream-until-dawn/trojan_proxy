//go:build integration

package gateway_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// TestRealMultiHostHTTP01 同一80/443完成逐域签发、隔离、后台候选和短期续期。
func TestRealMultiHostHTTP01(t *testing.T) {
	ctx := context.Background()
	caPEM, e := os.ReadFile("/fixture/ca.pem")
	if e != nil {
		t.Fatal(e)
	}
	apiRoots := x509.NewCertPool()
	apiRoots.AppendCertsFromPEM(caPEM)
	api := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: apiRoots}}}
	defer api.CloseIdleConnections()
	roots := x509.NewCertPool()
	deadline := time.Now().Add(10 * time.Second)
	for {
		r, e := api.Get("https://pebble:15000/roots/0")
		if e == nil {
			b, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
			r.Body.Close()
			if r.StatusCode == 200 && roots.AppendCertsFromPEM(b) {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Pebble root unavailable", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	makeBackend := func(label string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ws" && r.Header.Get("Upgrade") == "websocket" {
				serveFixtureWebSocket(w, r, label)
				return
			}
			io.Copy(io.Discard, r.Body)
			w.Header().Set("Cache-Control", "private, no-store")
			io.WriteString(w, label+"|"+r.Host+"|"+r.RequestURI+"|"+r.Header.Get("X-Forwarded-Proto"))
		}))
	}
	one, two, admin := makeBackend("one"), makeBackend("two"), makeBackend("admin")
	defer one.Close()
	defer two.Close()
	defer admin.Close()
	number := func(server *httptest.Server) int {
		_, p, _ := net.SplitHostPort(server.Listener.Addr().String())
		n, _ := strconv.Atoi(p)
		return n
	}
	s := gateway.Settings{Domain: "probe.test", AdminPath: "/proxy", AdminPort: 8007, ControlPort: number(admin), FilePort: 18091, Socket: "/run/caddy/admin.sock", Ingress: &gateway.Ingress{Mode: "automatic", AwaitCertificate: true}, Policy: routes.Policy{AdminPort: 8007, ControlPort: number(admin), FilePort: 18091, VPNPort: 18443, AllowStandardPorts: true}}
	for _, name := range []string{"one.probe.test", "two.probe.test", "proxy.probe.test", "missing.probe.test"} {
		s.Hosts = append(s.Hosts, gateway.Host{Name: name, Ingress: &gateway.Ingress{Mode: "automatic", AwaitCertificate: true}})
	}
	rules := []routes.Rule{{ID: "one", Name: "one", Port: 443, Host: "one.probe.test", Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: number(one), HTTPS: true}, {ID: "two", Name: "two", Port: 443, Host: "two.probe.test", Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: number(two), HTTPS: true}}
	engine := gateway.NewClient(s.Socket)
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, e = engine.Current(ctx); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	apply := func(body string) {
		t.Helper()
		var config map[string]any
		if e := json.Unmarshal([]byte(body), &config); e != nil {
			t.Fatal(e)
		}
		automation := config["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)
		automation["renew_interval"] = "1s"
		for _, p := range automation["policies"].([]any) {
			policy := p.(map[string]any)
			policy["renewal_window_ratio"] = 0.8
			issuer := policy["issuers"].([]any)[0].(map[string]any)
			issuer["ca"] = "https://pebble:14000/dir"
			issuer["test_ca"] = "https://pebble:14000/dir"
			issuer["trusted_roots_pem_files"] = []string{"/fixture/ca.pem"}
			issuer["acme_timeout"] = "15s"
		}
		encoded, _ := json.Marshal(config)
		if e := engine.Apply(ctx, string(encoded)); e != nil {
			t.Fatal("multi-host actual Caddy rejected config", e)
		}
	}
	body, e := gateway.Compile(s, rules)
	if e != nil {
		t.Fatal(e)
	}
	apply(body)
	pairs := map[string]certificates.Pair{}
	deadline = time.Now().Add(40 * time.Second)
	for len(pairs) < 4 {
		for _, name := range []string{"probe.test", "one.probe.test", "two.probe.test", "proxy.probe.test"} {
			if pair, e := certificates.ReadManaged("/cache/caddy/certificates", name, time.Now(), roots); e == nil {
				pairs[name] = pair
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("one failed domain blocked independent issuance", len(pairs))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, e = certificates.ReadManaged("/cache/caddy/certificates", "missing.probe.test", time.Now(), roots); e == nil {
		t.Fatal("unreachable DNS name got certificate")
	}
	if pairs["one.probe.test"].Metadata().Fingerprint == pairs["two.probe.test"].Metadata().Fingerprint {
		t.Fatal("domain certificates not independent")
	}
	s.Ingress.AwaitCertificate = false
	for i := range s.Hosts {
		if s.Hosts[i].Name != "missing.probe.test" {
			s.Hosts[i].Ingress.AwaitCertificate = false
		}
	}
	body, e = gateway.Compile(s, rules)
	if e != nil {
		t.Fatal(e)
	}
	apply(body)
	request := func(name, host, path, expected string, status int) {
		t.Helper()
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, "127.0.0.1:443")
		}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Timeout: 3 * time.Second, Transport: tr}
		r, _ := http.NewRequest("GET", "https://"+name+path, nil)
		r.Host = host
		r.Header.Set("X-Forwarded-Proto", "http")
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(name, e)
		}
		b, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != status || !strings.Contains(string(b), expected) {
			t.Fatal("hostname isolation changed", name, host, string(b), response.StatusCode, status)
		}
	}
	request("one.probe.test", "one.probe.test", "/same?x=1", "one|one.probe.test|/same?x=1|https", 200)
	request("two.probe.test", "two.probe.test", "/same?x=1", "two|two.probe.test|/same?x=1|https", 200)
	checkHostWebSocket(t, roots, "one.probe.test", "one")
	checkHostWebSocket(t, roots, "two.probe.test", "two")
	request("probe.test", "probe.test", "/proxy/test", "admin|probe.test", 200)
	request("one.probe.test", "unknown.probe.test", "/same", "", 404)
	if c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:443", &tls.Config{RootCAs: roots, ServerName: "unknown.probe.test"}); e == nil {
		c.Close()
		t.Fatal("unregistered SNI accepted")
	}
	next := s
	next.AdminPath = ""
	next.AdminDomain = "proxy.probe.test"
	body, e = gateway.CompileAdminTransition(s, next, rules)
	if e != nil {
		t.Fatal(e)
	}
	apply(body)
	request("probe.test", "probe.test", "/proxy/test", "admin|probe.test", 200)
	request("proxy.probe.test", "proxy.probe.test", "/api/test", "admin|proxy.probe.test|/api/test|https", 200)
	request("one.probe.test", "one.probe.test", "/", "one|", 200)
	body, e = gateway.Compile(next, rules)
	if e != nil {
		t.Fatal(e)
	}
	apply(body)
	request("proxy.probe.test", "proxy.probe.test", "/", "admin|", 200)
	first := pairs["one.probe.test"].Metadata().Fingerprint
	deadline = time.Now().Add(35 * time.Second)
	for {
		pair, e := certificates.ReadManaged("/cache/caddy/certificates", "one.probe.test", time.Now(), roots)
		if e == nil && pair.Metadata().Fingerprint != first {
			conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:443", &tls.Config{RootCAs: roots, ServerName: "one.probe.test"})
			if e == nil {
				digest := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
				conn.Close()
				if hex.EncodeToString(digest[:]) == pair.Metadata().Fingerprint {
					break
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("per-host renewal not served by TLS")
		}
		time.Sleep(100 * time.Millisecond)
	}
	request("two.probe.test", "two.probe.test", "/same", "two|", 200)
	t.Log("independent HTTP01, failed-host isolation, same-path host routing, administrator dual-entry and actual renewal passed")
}

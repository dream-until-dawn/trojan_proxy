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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// testPrefixRoutingContract 验证前缀开关的实际URI与边界，不替上游重写资源、跳转或Cookie。
func testPrefixRoutingContract(t *testing.T, engine *gateway.Client, settings gateway.Settings) {
	t.Helper()
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
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "fixture=sentinel; Path=/; Secure; HttpOnly; SameSite=Strict")
		if strings.HasSuffix(r.URL.Path, "/redirect") {
			w.Header().Set("Location", "/login")
			w.WriteHeader(303)
			return
		}
		body, _ := io.ReadAll(r.Body)
		json.NewEncoder(w).Encode(map[string]string{"uri": r.RequestURI, "method": r.Method, "body": string(body)})
	}))
	defer backend.Close()
	_, number, _ := net.SplitHostPort(backend.Listener.Addr().String())
	upstream, _ := strconv.Atoi(number)
	certificate, err := os.ReadFile("/certs/fullchain.cer")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("fixture root invalid")
	}
	settings.Domain = "localhost.test"
	publicPort := port(t)
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(publicPort))
	host := net.JoinHostPort(settings.Domain, strconv.Itoa(publicPort))
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: settings.Domain, RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, strip := range []bool{false, true} {
		rule := routes.Rule{ID: "prefix", Name: "路径契约", Port: publicPort, Host: settings.Domain, Path: "/futures", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: upstream, HTTPS: true, StripPrefix: strip}
		body, err := gateway.Compile(settings, []routes.Rule{rule})
		if err != nil {
			t.Fatal(err)
		}
		if err = engine.Apply(ctx, body); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/futures", "/futures/", "/futures/login?next=overview", "/futures/_next/static/fixture.js", "/futures/api/overview"} {
			expected := path
			if strip {
				expected = strings.TrimPrefix(path, "/futures")
				if expected == "" {
					expected = "/"
				}
			}
			request, _ := http.NewRequest("POST", "https://"+host+path, strings.NewReader("action=fixture"))
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			var actual map[string]string
			err = json.NewDecoder(response.Body).Decode(&actual)
			response.Body.Close()
			if err != nil || response.StatusCode != 200 || actual["uri"] != expected || actual["method"] != "POST" || actual["body"] != "action=fixture" {
				t.Fatal("prefix routing contract changed", strip, path, expected, actual, err)
			}
		}
		response, err := client.Get("https://" + host + "/futures-other")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatal("prefix boundary matched sibling path", strip, response.StatusCode)
		}
		response, err = client.Get("https://" + host + "/futures/redirect")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 303 || response.Header.Get("Location") != "/login" || !strings.Contains(response.Header.Get("Set-Cookie"), "Path=/;") {
			t.Fatal("proxy unexpectedly rewrote upstream redirects or cookie path", strip)
		}
	}
}

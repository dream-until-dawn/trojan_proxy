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
	"sync"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// testCustomHTTPS 以真实Caddy核验自定义TLS、非默认端口同源语义与流式响应。
func testCustomHTTPS(t *testing.T, engine *gateway.Client, settings gateway.Settings) {
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
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "first\n")
			w.(http.Flusher).Flush()
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			io.WriteString(w, "second\n")
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "fixture=sentinel; Path=/; Secure; HttpOnly; SameSite=Strict")
		json.NewEncoder(w).Encode(map[string]string{"host": r.Host, "forwarded_host": r.Header.Get("X-Forwarded-Host"), "proto": r.Header.Get("X-Forwarded-Proto"), "cookie": r.Header.Get("Cookie"), "origin": r.Header.Get("Origin"), "method": r.Method, "body": string(body)})
	}))
	defer backend.Close()
	_, number, _ := net.SplitHostPort(backend.Listener.Addr().String())
	upstream, _ := strconv.Atoi(number)
	settings.Domain = "localhost.test"
	publicPort := port(t)
	rule := routes.Rule{ID: "https-app", Name: "HTTPS入口", Port: publicPort, Host: settings.Domain, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: upstream, HTTPS: true}
	body, err := gateway.Compile(settings, []routes.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(ctx, body); err != nil {
		t.Fatal("custom HTTPS configuration rejected", err)
	}
	if status, _ := fetch(t, publicPort, "/"); status == 200 {
		t.Fatal("custom HTTPS accepted plaintext upstream access")
	}
	certificate, err := os.ReadFile("/certs/fullchain.cer")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("fixture certificate invalid")
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(publicPort))
	host := net.JoinHostPort(settings.Domain, strconv.Itoa(publicPort))
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: settings.Domain, RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequest("POST", "https://"+host+"/action", strings.NewReader("action=fixture&payload=value"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", "https://"+host)
	request.Header.Set("Cookie", "fixture=sentinel")
	request.Header.Set("X-Forwarded-Host", "spoof.invalid")
	request.Header.Set("X-Forwarded-Proto", "http")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("custom HTTPS trusted request failed", err)
	}
	var echoed map[string]string
	err = json.NewDecoder(response.Body).Decode(&echoed)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		t.Fatal("custom HTTPS POST failed", err, response.StatusCode)
	}
	if echoed["host"] != host || echoed["forwarded_host"] != host || echoed["proto"] != "https" {
		t.Fatal("custom HTTPS lost trusted origin headers", echoed)
	}
	if echoed["method"] != "POST" || echoed["body"] != "action=fixture&payload=value" || echoed["cookie"] != "fixture=sentinel" || echoed["origin"] != "https://"+host {
		t.Fatal("custom HTTPS changed action or cookie", echoed)
	}
	if !strings.Contains(response.Header.Get("Set-Cookie"), "Secure; HttpOnly; SameSite=Strict") {
		t.Fatal("custom HTTPS stripped cookie attributes")
	}
	// 匹配证书的正确SNI但未知Host也不能转发。
	for _, path := range []string{"/", "/robots.txt"} {
		request, _ = http.NewRequest("GET", "https://"+host+path, nil)
		request.Host = "unknown.invalid"
		response, err = client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 404 {
			t.Fatal("custom HTTPS accepted unknown Host", path, response.StatusCode)
		}
	}
	for _, serverName := range []string{"localhost", "untrusted.invalid"} {
		connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12})
		if connection != nil {
			connection.Close()
		}
		if err == nil {
			t.Fatal("custom HTTPS accepted non-authorized SNI", serverName)
		}
	}
	response, err = client.Get("https://" + host + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, len("first\n"))
	_, err = io.ReadFull(response.Body, first)
	if err != nil || string(first) != "first\n" {
		response.Body.Close()
		t.Fatal("custom HTTPS buffered initial stream chunk", err)
	}
	releaseOnce.Do(func() { close(release) })
	tail, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(tail) != "second\n" {
		t.Fatal("custom HTTPS stream tail failed", err)
	}
}

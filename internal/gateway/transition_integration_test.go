//go:build integration

package gateway_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

func testAdminEntryTransition(t *testing.T, engine *gateway.Client, current gateway.Settings, ruleset []routes.Rule) {
	t.Helper()
	ctx := context.Background()
	original, err := engine.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := engine.Apply(ctx, original); err != nil {
			t.Error("restore after admin entry probe", err)
		}
	}()
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(current.ControlPort)))
	if err != nil {
		t.Fatal(err)
	}
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "admin-fixture:"+r.Host) }))
	fixture.Listener = listener
	fixture.Start()
	defer fixture.Close()
	pem, err := os.ReadFile("/certs/fullchain.cer")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	request := func(domain string, port int) string {
		t.Helper()
		client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{ServerName: domain, RootCAs: roots}, DisableKeepAlives: true}}
		req, _ := http.NewRequest("GET", "https://127.0.0.1:"+strconv.Itoa(port)+"/", nil)
		req.Host = net.JoinHostPort(domain, strconv.Itoa(port))
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("trusted admin endpoint request failed", domain, port, err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != 200 {
			t.Fatal("admin endpoint unavailable", response.StatusCode, err)
		}
		return string(body)
	}
	candidate := current
	candidate.Domain = "localhost.test"
	candidate.AdminPort = port(t)
	candidate.Policy.AdminPort = candidate.AdminPort
	dual, err := gateway.CompileAdminTransition(current, candidate, ruleset)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(ctx, dual); err != nil {
		t.Fatal("dual admin listeners rejected by real gateway", err)
	}
	if request(current.Domain, current.AdminPort) != "admin-fixture:"+net.JoinHostPort(current.Domain, strconv.Itoa(current.AdminPort)) {
		t.Fatal("old admin endpoint lost during transition")
	}
	if request(candidate.Domain, candidate.AdminPort) != "admin-fixture:"+net.JoinHostPort(candidate.Domain, strconv.Itoa(candidate.AdminPort)) {
		t.Fatal("candidate admin endpoint missing")
	}
	// 同端口换域名也必须保留两套精确Host，不可让旧路由或404吞掉新Host。
	samePort := candidate
	samePort.AdminPort = current.AdminPort
	samePort.Policy.AdminPort = current.AdminPort
	dual, err = gateway.CompileAdminTransition(current, samePort, ruleset)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(ctx, dual); err != nil {
		t.Fatal("same-port dual domain entry rejected", err)
	}
	request(current.Domain, current.AdminPort)
	request(samePort.Domain, samePort.AdminPort)
	final, err := gateway.Compile(candidate, ruleset)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(ctx, final); err != nil {
		t.Fatal(err)
	}
	request(candidate.Domain, candidate.AdminPort)
	if connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(current.AdminPort)), time.Second); err == nil {
		connection.Close()
		t.Fatal("old admin listener remained after final entry switch")
	}
}

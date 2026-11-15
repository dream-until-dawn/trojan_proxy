//go:build integration

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"github.com/dream-until-dawn/trojan_proxy/internal/subscription"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

func TestRealSubscriptionIngress(t *testing.T) {
	ctx := context.Background()
	ownerDB, err := storage.OpenJournal(ctx, "/state/control.db", control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer ownerDB.Close()
	key := make([]byte, 32)
	secret, _ := auth.NewTOTPSecret()
	encrypted, _ := auth.EncryptSecret(key, secret)
	password := "subscription-fixture-password-only"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if err = ownerDB.CreateAccount(ctx, storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: -1, Recovery: []string{auth.TokenHash("fixture-recovery")}}); err != nil {
		t.Fatal(err)
	}
	authentication := auth.NewService(ownerDB, key)
	entry := adminentry.Endpoint{Origin: "https://localhost.test", Prefix: "/proxy"}
	adminToken, err := authentication.LoginAt(ctx, password, "", "fixture-recovery", entry.Identity())
	if err != nil {
		t.Fatal(err)
	}
	store, err := subscription.Open(ctx, "/state/subscription.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	nodeSecret := strings.Repeat("subscription-node-fixture-", 2)
	manager := subscription.New(store, authentication.CredentialBinding, func(context.Context) ([]byte, error) {
		return vpn.ExportClash(vpn.Settings{Domain: "localhost.test", Port: 18443, OwnAddresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Resolver: netip.MustParseAddrPort("1.1.1.1:53")}, vpn.Desired{Enabled: true, Password: nodeSecret, CertificateVersion: strings.Repeat("a", 64)})
	})
	apiServer := httptest.NewServer((&Server{Auth: authentication, Subscriptions: manager, EndpointsProvider: func() []adminentry.Endpoint { return []adminentry.Endpoint{entry} }}).Handler())
	defer apiServer.Close()
	address, _ := url.Parse(apiServer.URL)
	_, portText, _ := net.SplitHostPort(address.Host)
	port, _ := strconv.Atoi(portText)
	settings := gateway.Settings{Domain: "localhost.test", AdminPath: "/proxy", AdminPort: 18007, ControlPort: port, FilePort: 18091, Socket: "/run/caddy/admin.sock", AccessLog: true, Policy: routes.Policy{AllowStandardPorts: true, VPNPort: 18443}, Ingress: &gateway.Ingress{Mode: "manual", Certificate: "/certificates/test/fullchain.cer", Key: "/certificates/test/private.key"}}
	engine := gateway.NewClient("/run/caddy/admin.sock")
	deadline := time.Now().Add(8 * time.Second)
	for {
		if _, err = engine.Current(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture gateway not ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
	compiled, err := gateway.Compile(settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = engine.Apply(ctx, compiled); err != nil {
		t.Fatal(err)
	}
	certificate, err := os.ReadFile("/certs/fullchain.cer")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("fixture CA invalid")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost.test", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, "127.0.0.1:443")
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, path, token, body string) (int, []byte, http.Header) {
		t.Helper()
		r, _ := http.NewRequest(method, "https://localhost.test"+path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("Origin", entry.Origin)
			r.Header.Set("Content-Type", "application/json")
		}
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		data, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, data, response.Header
	}
	code, data, _ := call("POST", "/proxy/api/subscriptions/create", adminToken, `{"name":"probe"}`)
	if code != 200 {
		t.Fatal("real recent MFA creation failed", code)
	}
	var created struct {
		Item subscription.Record `json:"item"`
		URL  string              `json:"url"`
	}
	if json.Unmarshal(data, &created) != nil {
		t.Fatal("creation JSON invalid")
	}
	u, _ := url.Parse(created.URL)
	token := u.Query().Get("token")
	if len(token) != 43 {
		t.Fatal("missing created subscription token")
	}
	code, profile, headers := call("GET", u.RequestURI(), "", "")
	if code != 200 || !strings.Contains(string(profile), nodeSecret) || headers.Get("Cache-Control") != "no-store" {
		t.Fatal("real gateway subscription GET failed", code)
	}
	if !strings.Contains(string(profile), "DOMAIN,localhost.test,DIRECT") {
		t.Fatal("subscription direct update rule missing")
	}
	if err = os.WriteFile("/state/subscription-profile.yaml", profile, 0600); err != nil {
		t.Fatal(err)
	}
	code, _, _ = call("POST", "/proxy/api/status", token, `{}`)
	if code != 401 {
		t.Fatal("subscription token granted admin scope", code)
	}
	code, _, _ = call("GET", "/proxy/subscription/clash?token="+token+"&token=duplicate", "", "")
	if code != 404 {
		t.Fatal("duplicate subscription credential accepted", code)
	}
	code, _, _ = call("POST", "/proxy/api/subscriptions/revoke", adminToken, `{"id":"`+created.Item.ID+`"}`)
	if code != 200 {
		t.Fatal("real revocation failed", code)
	}
	code, _, _ = call("GET", u.RequestURI(), "", "")
	if code != 404 {
		t.Fatal("real gateway accepted revoked URL", code)
	}
	var logs []byte
	deadline = time.Now().Add(3 * time.Second)
	for {
		entries, _ := os.ReadDir("/data/access")
		logs = nil
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".log") {
				b, _ := os.ReadFile(filepath.Join("/data/access", e.Name()))
				logs = append(logs, b...)
			}
		}
		if strings.Contains(string(logs), "/proxy/subscription/clash") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("subscription access log missing")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if strings.Contains(string(logs), token) || strings.Contains(string(logs), nodeSecret) || strings.Contains(string(logs), adminToken) || strings.Contains(string(logs), "token=") {
		t.Fatal("subscription secret written to gateway access log")
	}
	markers, _ := json.Marshal([]string{token, nodeSecret, adminToken})
	if err = os.WriteFile("/state/subscription-markers.json", markers, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("real HTTPS subscription, recent MFA, scoped token, revoked URL, and pre-write log redaction passed")
}

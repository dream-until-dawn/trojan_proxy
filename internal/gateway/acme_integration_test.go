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
	"os"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// TestRealHTTP01AndRenewal 使用隔离的Pebble，禁止跳过挑战验证或关闭TLS校验。
func TestRealHTTP01AndRenewal(t *testing.T) {
	fixture, err := os.ReadFile("/fixture/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	apiRoots := x509.NewCertPool()
	if !apiRoots.AppendCertsFromPEM(fixture) {
		t.Fatal("Pebble API测试根无效")
	}
	apiClient := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: apiRoots}}}
	var ca []byte
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, e := apiClient.Get("https://pebble:15000/roots/0")
		if e == nil {
			ca, e = io.ReadAll(io.LimitReader(response.Body, 65536))
			response.Body.Close()
			if e == nil && response.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Pebble管理API未就绪", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("签发根无效")
	}
	settings := gateway.Settings{Domain: "probe.test", AdminPort: 8007, ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443, AllowStandardPorts: true}, Ingress: &gateway.Ingress{Mode: "automatic"}}
	body, err := gateway.Compile(settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err = json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	automation := config["apps"].(map[string]any)["tls"].(map[string]any)["automation"].(map[string]any)
	automation["renew_interval"] = "1s"
	policy := automation["policies"].([]any)[0].(map[string]any)
	policy["renewal_window_ratio"] = 0.8
	issuer := policy["issuers"].([]any)[0].(map[string]any)
	issuer["ca"] = "https://pebble:14000/dir"
	issuer["test_ca"] = "https://pebble:14000/dir"
	issuer["trusted_roots_pem_files"] = []string{"/fixture/ca.pem"}
	issuer["acme_timeout"] = "15s"
	bodyBytes, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	engine := gateway.NewClient(settings.Socket)
	deadline = time.Now().Add(10 * time.Second)
	for {
		if _, err = engine.Current(context.Background()); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err = engine.Apply(context.Background(), string(bodyBytes)); err != nil {
		t.Fatal("自动配置加载失败", err)
	}
	var first certificates.Prepared
	for _, phase := range []string{"issuance", "renewal"} {
		deadline = time.Now().Add(35 * time.Second)
		var pair certificates.Pair
		for {
			pair, err = certificates.ReadManaged("/cache/caddy/certificates", "probe.test", time.Now(), roots)
			if err == nil && (phase == "issuance" || pair.Metadata().Fingerprint != first.Info.Fingerprint) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("HTTP-01签发或续期未完成", phase, err)
			}
			time.Sleep(200 * time.Millisecond)
		}
		prepared, err := certificates.Prepare("/published", pair)
		if err != nil {
			t.Fatal(err)
		}
		// 缓存已更新并不意味着运行证书已更新；独立验证实际TLS握手指纹。
		deadline = time.Now().Add(5 * time.Second)
		for {
			conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:443", &tls.Config{RootCAs: roots, ServerName: "probe.test", MinVersion: tls.VersionTLS12})
			if e == nil {
				digest := sha256.Sum256(conn.ConnectionState().PeerCertificates[0].Raw)
				conn.Close()
				if hex.EncodeToString(digest[:]) == prepared.Info.Fingerprint {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatal("实际握手没有加载最新证书", phase, e)
			}
			time.Sleep(100 * time.Millisecond)
		}
		if phase == "issuance" {
			first = prepared
		} else if prepared.Version == first.Version {
			t.Fatal("续期未发布新版本")
		}
		t.Log("ACME阶段与实际握手通过:", phase)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", "http://127.0.0.1/check?q=1", nil)
	req.Host = "probe.test"
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 308 || response.Header.Get("Location") != "https://probe.test/check?q=1" {
		t.Fatal("签发后HTTP跳转异常")
	}
	if conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:443", &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "probe.test"}); err == nil {
		conn.Close()
		t.Fatal("不可信证书被接受")
	}
}

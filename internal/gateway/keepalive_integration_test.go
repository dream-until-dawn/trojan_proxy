//go:build integration

package gateway_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
)

// testInternalKeepalive 使用真实TCP重置模拟已失效的复用连接；不依赖分钟级随机时序。
func testInternalKeepalive(t *testing.T, engine *gateway.Client, settings gateway.Settings) {
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
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var accepted, reset atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				reader := bufio.NewReader(conn)
				for index := 0; index < 2; index++ {
					request, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					if index == 1 {
						reset.Add(1)
						conn.(*net.TCPConn).SetLinger(0)
						return
					}
					io.Copy(io.Discard, request.Body)
					request.Body.Close()
					fmt.Fprint(conn, "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}")
				}
			}(conn)
		}
	}()
	settings.ControlPort = listener.Addr().(*net.TCPAddr).Port
	body, err := gateway.Compile(settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err = json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	admin := config["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["admin"].(map[string]any)
	var proxy map[string]any
	for _, route := range admin["routes"].([]any) {
		for _, handler := range route.(map[string]any)["handle"].([]any) {
			candidate := handler.(map[string]any)
			if candidate["handler"] == "reverse_proxy" {
				proxy = candidate
			}
		}
	}
	if proxy == nil {
		t.Fatal("compiled admin proxy missing")
	}
	certificate, err := os.ReadFile("/certs/fullchain.cer")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificate) {
		t.Fatal("测试证书无效")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	post := func() int {
		t.Helper()
		request, err := http.NewRequest("POST", "https://127.0.0.1:"+strconv.Itoa(settings.AdminPort)+"/api/vpn/status", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "localhost"
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}
	apply := func(value map[string]any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = engine.Apply(ctx, string(data)); err != nil {
			t.Fatal(err)
		}
	}
	// 负向对照：移除产品保护后必须在第二个POST得到502，且上游确实发生重置。
	protection := proxy["transport"]
	delete(proxy, "transport")
	apply(config)
	first, second := post(), post()
	if first != 401 || second != 502 || reset.Load() != 1 {
		t.Fatalf("stale connection negative control did not produce 502: first=%d second=%d resets=%d accepted=%d", first, second, reset.Load(), accepted.Load())
	}
	proxy["transport"] = protection
	apply(config)
	before, oldReset := accepted.Load(), reset.Load()
	for index := 0; index < 4; index++ {
		if status := post(); status != 401 {
			t.Fatalf("internal POST reused stale connection: %d", status)
		}
	}
	if accepted.Load()-before != 4 || reset.Load() != oldReset {
		t.Fatal("internal requests reused upstream connection")
	}
}

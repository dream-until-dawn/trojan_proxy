//go:build integration

package gateway_test

import (
	"bufio"
	"crypto/sha1" // RFC6455握手规定的SHA1，仅测试协议，不用于口令或签名。
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func serveFixtureWebSocket(w http.ResponseWriter, r *http.Request, label string) {
	conn, rw, e := w.(http.Hijacker).Hijack()
	if e != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	digest := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(digest[:]))
	if rw.Flush() != nil {
		return
	}
	header := make([]byte, 2)
	if _, e = io.ReadFull(rw, header); e != nil || header[1]&0x80 == 0 || header[1]&127 > 125 {
		return
	}
	mask := make([]byte, 4)
	if _, e = io.ReadFull(rw, mask); e != nil {
		return
	}
	payload := make([]byte, int(header[1]&127))
	if _, e = io.ReadFull(rw, payload); e != nil {
		return
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	answer := []byte(label + ":" + string(payload))
	rw.Write([]byte{0x81, byte(len(answer))})
	rw.Write(answer)
	rw.Flush()
}

// checkHostWebSocket 验证真正的101握手和双向帧，不能只凭Upgrade请求返回200算通过。
func checkHostWebSocket(t *testing.T, roots *x509.CertPool, name, label string) {
	t.Helper()
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:443", &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nOrigin: https://%s\r\n\r\n", name, name)
	reader := bufio.NewReader(conn)
	response, e := http.ReadResponse(reader, nil)
	if e != nil || response.StatusCode != 101 || response.Header.Get("Sec-WebSocket-Accept") != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatal("actual WebSocket handshake failed", e)
	}
	if _, e = conn.Write([]byte{0x81, 0x82, 1, 2, 3, 4, 'h' ^ 1, 'i' ^ 2}); e != nil {
		t.Fatal(e)
	}
	header := make([]byte, 2)
	if _, e = io.ReadFull(reader, header); e != nil {
		t.Fatal(e)
	}
	payload := make([]byte, int(header[1]&127))
	if _, e = io.ReadFull(reader, payload); e != nil || string(payload) != label+":hi" {
		t.Fatal("WebSocket crossed host or lost frames", string(payload), e)
	}
}

//go:build integration

package vpn

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestWriteEngineFixture 仅生成临时测试配置，秘密是固定测试材料，不能部署使用。
func TestWriteEngineFixture(t *testing.T) {
	s := Settings{Domain: "vpn.test", Port: 18443, OwnAddresses: []netip.Addr{netip.MustParseAddr("198.51.100.10")}, Resolver: netip.MustParseAddrPort("198.51.100.53:53")}
	d := Desired{Enabled: true, Password: "fixture-only-password-0123456789abcdef", CertificateVersion: strings.Repeat("a", 64)}
	body, err := CompileTrojan(s, d)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/fixture/server.json", []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	// 固定假口令的临时夹具须供不同UID镜像读取；产品运行配置仍必须0600。
	if err = os.Chmod("/fixture/server.json", 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRealTrojanEgressAndUDP(t *testing.T) {
	proxy, _ := url.Parse("http://127.0.0.1:7890")
	client := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	fetch := func(target string) (int, string, error) {
		response, err := client.Get("http://" + target + ":8000/")
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 4096))
		return response.StatusCode, string(body), err
	}
	if os.Getenv("TROJAN_VPN_PHASE") != "good" {
		if status, body, err := fetch("198.51.100.20"); err == nil && status == 200 && body == "public-sentinel" {
			t.Fatal("错误口令或证书仍能读取哨兵")
		}
		return
	}
	for _, target := range []string{"198.51.100.20", "public.test", "rebind.test"} {
		if status, body, err := fetch(target); err != nil || status != 200 || body != "public-sentinel" {
			t.Fatal("真实TCP代理失败", target, status, body, err)
		}
	}
	for _, target := range []string{"127.0.0.1", "198.51.100.10", "private.test", "rebind.test"} {
		if status, body, err := fetch(target); err == nil && status == 200 {
			t.Fatal("目的地址保护失效", target, body)
		}
	}
	if body, err := udpViaSOCKS("198.51.100.20:8001"); err != nil || !bytes.Equal(body, []byte("udp-sentinel")) {
		t.Fatal("真实Trojan UDP失败", string(body), err)
	}
	if body, err := udpViaSOCKS("127.0.0.1:8001"); err == nil {
		t.Fatal("UDP目的地址保护失效", string(body))
	}
}

func udpViaSOCKS(target string) ([]byte, error) {
	control, err := net.DialTimeout("tcp", "127.0.0.1:7890", time.Second)
	if err != nil {
		return nil, err
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = control.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	var choice [2]byte
	if _, err = io.ReadFull(control, choice[:]); err != nil {
		return nil, err
	}
	if choice != [2]byte{5, 0} {
		return nil, io.ErrUnexpectedEOF
	}
	// SOCKS5 UDP ASSOCIATE；TCP控制连接必须保持到UDP响应完成。
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	var header [4]byte
	if _, err = io.ReadFull(control, header[:]); err != nil {
		return nil, err
	}
	if header[1] != 0 {
		return nil, io.ErrUnexpectedEOF
	}
	addressLength := 4
	if header[3] == 4 {
		addressLength = 16
	} else if header[3] != 1 {
		return nil, io.ErrUnexpectedEOF
	}
	address := make([]byte, addressLength+2)
	if _, err = io.ReadFull(control, address); err != nil {
		return nil, err
	}
	// relay与探针共享网络命名空间，不依赖0.0.0.0/::这种不可拨号地址。
	relay := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(binary.BigEndian.Uint16(address[addressLength:]))}
	conn, err := net.DialUDP("udp4", nil, relay)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	destination, err := netip.ParseAddrPort(target)
	if err != nil {
		return nil, err
	}
	ip := destination.Addr().As4()
	packet := []byte{0, 0, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(destination.Port() >> 8), byte(destination.Port())}
	packet = append(packet, []byte("udp-sentinel")...)
	if _, err = conn.Write(packet); err != nil {
		return nil, err
	}
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	if n < 10 || buffer[2] != 0 || buffer[3] != 1 {
		return nil, io.ErrUnexpectedEOF
	}
	return buffer[10:n], nil
}

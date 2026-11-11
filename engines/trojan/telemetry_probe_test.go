//go:build integration

// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/engines/trojan/telemetry"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
)

type eventRecorder struct {
	mu     sync.Mutex
	events []telemetry.Event
}

func (r *eventRecorder) Record(e telemetry.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}
func (r *eventRecorder) sum(network string, address netip.AddrPort) (int64, int64, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var up, down, connections int64
	for _, e := range r.events {
		if e.Network == network && e.Target == address {
			up += e.Upload
			down += e.Download
			connections += e.Connections
		}
	}
	return up, down, connections
}

func TestActualOutboundTelemetryTCPFallbackAndUDP(t *testing.T) {
	recorder := &eventRecorder{}
	ctx := registryContextWithRecorder(recorder)
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{"log":{"disabled":true},"dns":{"servers":[{"type":"udp","server":"127.0.0.1","server_port":9}]},"outbounds":[{"type":"direct","tag":"public","connect_timeout":"1s"}],"route":{"final":"public"}}`))
	if err != nil {
		t.Fatal(err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	outbound, ok := instance.Outbound().Outbound("public")
	if !ok {
		t.Fatal("missing observed direct outbound")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	actual := netip.MustParseAddrPort(listener.Addr().String())
	// ::1没有监听，域名也不存在；只有实际成功的127.0.0.1可以成为统计目标。
	destination := M.Socksaddr{Fqdn: "does-not-resolve.invalid", Port: actual.Port()}
	conn, err := dialer.DialSerialNetwork(context.Background(), outbound, "tcp", destination, []netip.Addr{netip.IPv6Loopback(), actual.Addr()}, nil, nil, nil, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("payload"), 512)
	if _, err = io.Copy(conn, bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, received); err != nil || !bytes.Equal(received, payload) {
		t.Fatal("TCP echo failed", err)
	}
	up, down, connections := recorder.sum("tcp", actual)
	if up != int64(len(payload)) || down != up || connections != 1 {
		t.Fatalf("TCP exact payload count incorrect: %d %d %d", up, down, connections)
	}
	if up, down, connections = recorder.sum("tcp", netip.AddrPortFrom(netip.IPv6Loopback(), actual.Port())); up != 0 || down != 0 || connections != 0 {
		t.Fatal("failed DNS candidate was recorded as successful target")
	}
	halfListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer halfListener.Close()
	go func() {
		server, e := halfListener.Accept()
		if e != nil {
			return
		}
		defer server.Close()
		io.ReadAll(server)
		server.Write([]byte("after-eof"))
	}()
	halfTarget := netip.MustParseAddrPort(halfListener.Addr().String())
	half, err := outbound.DialContext(context.Background(), "tcp", M.SocksaddrFrom(halfTarget.Addr(), halfTarget.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer half.Close()
	half.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = half.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	closer, ok := half.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("telemetry removed TCP half-close")
	}
	if err = closer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	late, err := io.ReadAll(half)
	if err != nil || string(late) != "after-eof" {
		t.Fatal("telemetry truncated response after TCP half-close", string(late), err)
	}
	for _, address := range []string{"127.0.0.1:0", "127.0.0.2:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			server, e := net.ListenPacket("udp", address)
			if e != nil {
				t.Fatal(e)
			}
			defer server.Close()
			go func() {
				buffer := make([]byte, 4096)
				for {
					n, remote, e := server.ReadFrom(buffer)
					if e != nil {
						return
					}
					server.WriteTo(buffer[:n], remote)
				}
			}()
			target := netip.MustParseAddrPort(server.LocalAddr().String())
			packet, e := outbound.ListenPacket(context.Background(), M.SocksaddrFrom(target.Addr(), target.Port()))
			if e != nil {
				t.Fatal(e)
			}
			defer packet.Close()
			packet.SetDeadline(time.Now().Add(3 * time.Second))
			body := []byte("udp-known-payload")
			if _, e = packet.WriteTo(body, server.LocalAddr()); e != nil {
				t.Fatal(e)
			}
			buffer := make([]byte, 1024)
			n, _, e := packet.ReadFrom(buffer)
			if e != nil || !bytes.Equal(buffer[:n], body) {
				t.Fatal("UDP echo failed", e)
			}
			up, down, _ := recorder.sum("udp", target)
			if up != int64(len(body)) || down != up {
				t.Fatalf("UDP actual target/payload count incorrect: %s %d %d", target, up, down)
			}
		})
	}
}

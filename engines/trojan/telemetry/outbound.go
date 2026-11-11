// SPDX-License-Identifier: GPL-3.0-or-later
// Package telemetry 在实际出站连接/数据包边界计量，不从DNS候选推测成功目标。
package telemetry

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
)

// Event 仅含实际目标和有效载荷计数；上层必须以有限队列/聚合接收，不能同步写盘。
type Event struct {
	Network          string
	Target           netip.AddrPort
	Upload, Download int64
	Connections      int64
}

// Recorder 不读取业务内容；实现必须快速返回，统计故障不得阻断代理。
type Recorder interface{ Record(Event) }

// Register 替换direct构造器但保留原生命周期和所有并行拨号路径。
func Register(registry *outbound.Registry, recorder Recorder) {
	outbound.Register[option.DirectOutboundOptions](registry, C.TypeDirect, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DirectOutboundOptions) (adapter.Outbound, error) {
		base, err := direct.NewOutbound(ctx, router, logger, tag, options)
		if err != nil {
			return nil, err
		}
		return &observedOutbound{Outbound: base.(*direct.Outbound), recorder: recorder}, nil
	})
}

type observedOutbound struct {
	*direct.Outbound
	recorder Recorder
}

func (o *observedOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := o.Outbound.DialContext(ctx, network, destination)
	if err != nil {
		return conn, err
	}
	return wrapConn(conn, network, o.recorder), err
}
func (o *observedOutbound) DialParallel(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr) (net.Conn, error) {
	conn, err := o.Outbound.DialParallel(ctx, network, destination, addresses)
	if err != nil {
		return conn, err
	}
	return wrapConn(conn, network, o.recorder), err
}
func (o *observedOutbound) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr, strategy *C.NetworkStrategy, types, fallbackTypes []C.InterfaceType, delay time.Duration) (net.Conn, error) {
	conn, err := o.Outbound.DialParallelNetwork(ctx, network, destination, addresses, strategy, types, fallbackTypes, delay)
	if err != nil {
		return conn, err
	}
	return wrapConn(conn, network, o.recorder), err
}
func (o *observedOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := o.Outbound.ListenPacket(ctx, destination)
	if err != nil {
		return conn, err
	}
	return wrapPacket(conn, o.recorder), err
}
func (o *observedOutbound) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, addresses []netip.Addr, strategy *C.NetworkStrategy, types, fallbackTypes []C.InterfaceType, delay time.Duration) (net.PacketConn, netip.Addr, error) {
	conn, address, err := o.Outbound.ListenSerialNetworkPacket(ctx, destination, addresses, strategy, types, fallbackTypes, delay)
	if err != nil {
		return conn, address, err
	}
	return wrapPacket(conn, o.recorder), address, err
}

func target(address net.Addr) netip.AddrPort {
	if address == nil {
		return netip.AddrPort{}
	}
	value, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(value.Addr().Unmap(), value.Port())
}

// 仅嵌入net.Conn接口，避免io.Copy或引擎Upstream优化绕过Read/Write计数。
type observedConn struct {
	net.Conn
	recorder Recorder
	network  string
	target   netip.AddrPort
}

func wrapConn(conn net.Conn, network string, recorder Recorder) net.Conn {
	if conn == nil {
		return nil
	}
	if recorder == nil {
		return conn
	}
	address := target(conn.RemoteAddr())
	if !address.IsValid() {
		return conn
	}
	if len(network) >= 3 {
		network = network[:3]
	}
	recorder.Record(Event{Network: network, Target: address, Connections: 1})
	return &observedConn{Conn: conn, recorder: recorder, network: network, target: address}
}
func (c *observedConn) Write(body []byte) (int, error) {
	n, err := c.Conn.Write(body)
	if n > 0 {
		c.recorder.Record(Event{Network: c.network, Target: c.target, Upload: int64(n)})
	}
	return n, err
}
func (c *observedConn) Read(body []byte) (int, error) {
	n, err := c.Conn.Read(body)
	if n > 0 {
		c.recorder.Record(Event{Network: c.network, Target: c.target, Download: int64(n)})
	}
	return n, err
}

// 保留TCP半关闭语义，不能因为加计数包装就截断服务端在EOF之后返回的数据。
func (c *observedConn) CloseWrite() error {
	if connection, ok := common.Cast[interface{ CloseWrite() error }](c.Conn); ok {
		return connection.CloseWrite()
	}
	return c.Conn.Close()
}

type observedPacket struct {
	net.PacketConn
	recorder Recorder
}

func wrapPacket(conn net.PacketConn, recorder Recorder) net.PacketConn {
	if conn == nil {
		return nil
	}
	if recorder == nil {
		return conn
	}
	return &observedPacket{PacketConn: conn, recorder: recorder}
}
func (c *observedPacket) WriteTo(body []byte, address net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(body, address)
	ip := target(address)
	if n > 0 && ip.IsValid() {
		c.recorder.Record(Event{Network: "udp", Target: ip, Upload: int64(n)})
	}
	return n, err
}
func (c *observedPacket) ReadFrom(body []byte) (int, net.Addr, error) {
	n, address, err := c.PacketConn.ReadFrom(body)
	ip := target(address)
	if n > 0 && ip.IsValid() {
		c.recorder.Record(Event{Network: "udp", Target: ip, Download: int64(n)})
	}
	return n, address, err
}

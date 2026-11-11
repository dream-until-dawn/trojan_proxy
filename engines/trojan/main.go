// SPDX-License-Identifier: GPL-3.0-or-later
// trojan-engine 仅注册首版所需模块，避免通用发行镜像引入无关执行入口。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/dream-until-dawn/trojan_proxy/engines/trojan/telemetry"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

func registryContext() context.Context {
	return registryContextWithRecorder(nil)
}

func registryContextWithRecorder(recorder telemetry.Recorder) context.Context {
	inbounds := inbound.NewRegistry()
	trojan.RegisterInbound(inbounds)
	outbounds := outbound.NewRegistry()
	if recorder == nil {
		direct.RegisterOutbound(outbounds)
	} else {
		telemetry.Register(outbounds, recorder)
	}
	transports := dns.NewTransportRegistry()
	transport.RegisterUDP(transports)
	return box.Context(service.ContextWithDefaultRegistry(context.Background()), inbounds, outbounds, endpoint.NewRegistry(), transports, boxservice.NewRegistry(), certificate.NewRegistry())
}

func run(args []string) error {
	if len(args) == 1 && args[0] == "version" {
		fmt.Println("trojan-engine sing-box v1.14.4; Trojan/direct/UDP-DNS only")
		return nil
	}
	if len(args) < 1 || (args[0] != "check" && args[0] != "run") {
		return errors.New("仅支持check或run")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := flags.String("c", "", "唯一配置文件")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("必须指定唯一配置文件")
	}
	file, err := os.Open(*path)
	if err != nil {
		return errors.New("无法打开引擎配置")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(body) > 65536 {
		return errors.New("引擎配置过大或不可读")
	}
	var sampler *telemetry.Sampler
	var recorder telemetry.Recorder
	if args[0] == "run" {
		sampler, _ = telemetry.NewSampler(256, 60)
		if sampler != nil {
			recorder = sampler
		}
	}
	ctx, cancel := context.WithCancel(registryContextWithRecorder(recorder))
	defer cancel()
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, body)
	if err != nil {
		return errors.New("引擎配置格式错误或使用了未启用的模块")
	}
	// 禁用配置不应出现的后台、缓存文件、NTP、证书服务与任意扩展。
	if options.Experimental != nil || options.NTP != nil || options.Certificate != nil || len(options.HTTPClients) > 0 || len(options.NetworkNamespaces) > 0 || len(options.Endpoints) > 0 || len(options.Services) > 0 || len(options.CertificateProviders) > 0 {
		return errors.New("引擎配置包含非授权功能")
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return errors.New("引擎配置校验失败")
	}
	defer instance.Close()
	if args[0] == "check" {
		return nil
	}
	if sampler != nil {
		// 统计失效不能阻断代理；固定路径只在runner专属共享目录创建，不开放TCP接口。
		if listener, err := telemetry.ListenUnix("/run/vpn/telemetry.sock"); err == nil {
			if exporter, err := telemetry.Serve(listener, sampler); err == nil {
				defer exporter.Close()
			} else {
				listener.Close()
			}
		}
	}
	if err = instance.Start(); err != nil {
		return errors.New("引擎启动失败")
	}
	signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-signalCtx.Done()
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

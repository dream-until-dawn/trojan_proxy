// vpnrunner 仅在Linux Docker运行，不开放任何TCP管理端口。
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpnrunner"
)

func run() error {
	path := flag.String("config", "/etc/trojan-proxy/proxy.json", "统一部署配置")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("存在未知执行器参数")
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if !c.VPNManagement && !c.StandardIngress {
		return errors.New("部署配置尚未启用VPN管理")
	}
	settings, err := vpn.SettingsFromConfig(c)
	if err != nil {
		return err
	}
	engine, err := vpnrunner.NewEngine(settings, "/usr/local/bin/trojan-engine", "/run/vpn/private")
	if err != nil {
		return err
	}
	defer engine.Close()
	const socket = "/run/vpn/control.sock"
	if stat, err := os.Lstat(socket); err == nil {
		// 只清理自己的失效Unix socket；文件、其他所有者或仍工作的服务均拒绝覆盖。
		owner, ok := stat.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Getuid()) || stat.Mode()&os.ModeSocket == 0 {
			return errors.New("执行器socket路径已被其他对象占用")
		}
		if connection, err := net.DialTimeout("unix", socket, time.Second); err == nil {
			connection.Close()
			return errors.New("已有VPN执行器运行")
		}
		if err = os.Remove(socket); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0660); err != nil {
		return err
	}
	server := &http.Server{Handler: engine.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		bounded, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(bounded) != nil {
			server.Close()
		}
	}()
	err = server.Serve(listener)
	stop()
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

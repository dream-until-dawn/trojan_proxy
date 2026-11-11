// control 提供回环管理服务，由HTTPS网关代理，不直接暴露明文公网登录。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/api"
	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/files"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	"github.com/dream-until-dawn/trojan_proxy/internal/routing"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"github.com/dream-until-dawn/trojan_proxy/internal/webui"
)

func run() error {
	path := flag.String("config", "proxy.json", "部署配置路径")
	flag.Parse()
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	s, err := storage.OpenJournal(context.Background(), filepath.Join(c.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		return err
	}
	defer s.Close()
	ready, err := s.Initialized(context.Background())
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("管理员尚未初始化，请在终端执行 proxyctl admin-init --config <配置文件>")
	}
	keyPath := filepath.Join(c.DataDir, "master.key")
	if _, err = os.Stat(keyPath); err != nil {
		return fmt.Errorf("主密钥缺失，必须从备份恢复: %w", err)
	}
	key, err := auth.LoadKey(keyPath)
	if err != nil {
		return err
	}
	local := "http://127.0.0.1:" + strconv.Itoa(c.ControlPort)
	origins := map[string]bool{local: true}
	if c.Domain != "" {
		origins["https://"+net.JoinHostPort(c.Domain, strconv.Itoa(c.AdminPort))] = true
	}
	filePort := c.ControlPort + 1
	settings := gateway.Settings{Domain: c.Domain, AdminPort: c.AdminPort, ControlPort: c.ControlPort, FilePort: filePort, Socket: "/run/caddy/admin.sock",
		Policy: routes.Policy{AdminPort: c.AdminPort, ControlPort: c.ControlPort, FilePort: filePort, VPNPort: c.VPNPort, Directories: c.PublicDirectories}}
	router := routing.NewService(s, gateway.NewClient(settings.Socket), settings)
	roots := map[string]*files.Root{}
	defer func() {
		for _, root := range roots {
			root.Close()
		}
	}()
	for id, path := range c.PublicDirectories {
		root, err := files.OpenRoot(path)
		if err != nil {
			return fmt.Errorf("公开目录%s无法打开: %w", id, err)
		}
		roots[id] = root
	}
	handler := (&api.Server{Auth: auth.NewService(s, key), Origins: origins, Static: webui.Handler(), Routes: router}).Handler()
	server := &http.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(c.ControlPort)), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8192}
	fileServer := &http.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(filePort)), Handler: &files.Handler{Roots: roots, Resolver: router}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	adminListener, err := net.Listen("tcp4", server.Addr)
	if err != nil {
		return err
	}
	defer adminListener.Close()
	fileListener, err := net.Listen("tcp4", fileServer.Addr)
	if err != nil {
		return err
	}
	defer fileListener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fileErrors := make(chan error, 1)
	reconcileDone := make(chan struct{})
	go func() {
		if err := fileServer.Serve(fileListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fileErrors <- err
			server.Close()
		}
	}()
	go func() {
		defer close(reconcileDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			check, cancel := context.WithTimeout(ctx, 15*time.Second)
			if err := router.Reconcile(check); err != nil && ctx.Err() == nil {
				log.Print("网关尚未收敛，业务配置修改暂停")
			}
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		drain, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(drain); err != nil {
			server.Close()
		}
		if err := fileServer.Shutdown(drain); err != nil {
			fileServer.Close()
		}
	}()
	err = server.Serve(adminListener)
	stop()
	<-shutdownDone
	<-reconcileDone
	select {
	case fileErr := <-fileErrors:
		return fileErr
	default:
	}
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

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

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/files"
	"github.com/dream-until-dawn/trojan_proxy/internal/maintenance"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"github.com/dream-until-dawn/trojan_proxy/internal/traffic"
	"github.com/dream-until-dawn/trojan_proxy/internal/webaccess"
	"github.com/dream-until-dawn/trojan_proxy/internal/webui"
)

func run() error {
	path := flag.String("config", "proxy.json", "部署配置路径")
	flag.Parse()
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	maintenanceLock, err := maintenance.Acquire(c.DataDir, false)
	if err != nil {
		return err
	}
	defer maintenanceLock.Close()
	if err = verifyRecoveryReady(c.DataDir); err != nil {
		return err
	}
	s, err := storage.OpenJournal(context.Background(), filepath.Join(c.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	key, err := prepareAdministrator(ctx, c, s)
	if err != nil {
		return err
	}
	filePort := c.ControlPort + 1
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
	management, err := newManagement(c, s, key, roots)
	if err != nil {
		return err
	}
	router, vpnManager := management.Router, management.VPN
	statistics := traffic.NewService(filepath.Join(c.DataDir, "traffic.db"), traffic.NewClient("/run/vpn/telemetry.sock"))
	statisticsDone := make(chan struct{})
	go func() { defer close(statisticsDone); statistics.Run(ctx) }()
	defer func() { stop(); <-statisticsDone }()
	management.API.Auth = auth.NewService(s, key)
	management.API.Static = webui.Handler()
	management.API.Traffic = statistics
	access := webaccess.NewService(filepath.Join(c.DataDir, "access.db"), "/caddy-data/access")
	accessDone := make(chan struct{})
	go func() { defer close(accessDone); access.Run(ctx) }()
	defer func() { stop(); <-accessDone }()
	management.API.WebAccess = access
	handler := management.API.Handler()
	server := &http.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(c.ControlPort)), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8192}
	fileHandler := &files.Handler{Roots: roots, Resolver: router}
	if management.View != nil {
		fileHandler.RootProvider = management.View.Directory
	}
	fileServer := &http.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(filePort)), Handler: fileHandler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
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
			prepareErr := management.Prepare(check)
			if prepareErr != nil && ctx.Err() == nil {
				log.Print("持久设置迁移或入口恢复尚未完成；可通过SSH隧道管理")
			}
			if prepareErr == nil {
				if err := router.Reconcile(check); err != nil && ctx.Err() == nil {
					log.Print("网关尚未收敛，业务配置修改暂停")
				}
			}
			cancel()
			if vpnManager != nil {
				check, cancel := context.WithTimeout(ctx, 35*time.Second)
				if err := vpnManager.Reconcile(check); err != nil && ctx.Err() == nil {
					log.Print("VPN尚未收敛，请核实证书和执行器状态")
				}
				cancel()
			}
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

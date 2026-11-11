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
	handler := (&api.Server{Auth: auth.NewService(s, key), Origins: origins, Static: webui.Handler()}).Handler()
	server := &http.Server{Addr: net.JoinHostPort("127.0.0.1", strconv.Itoa(c.ControlPort)), Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8192}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(drain)
	}()
	err = server.ListenAndServe()
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

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/bootstrap"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

// verifyRecoveryReady 在任何监听启动前阻止还原后的旧认证材料重新提供登录。
func verifyRecoveryReady(directory string) error {
	if _, err := os.Lstat(filepath.Join(directory, "recovery-required")); err == nil {
		return errors.New("冷还原后必须先通过SSH交互终端重新绑定管理员，再启动control")
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// prepareAdministrator 不为现有账户/未完成绑定静默生成替代密钥；新实例才创建主密钥。
func prepareAdministrator(ctx context.Context, c config.Config, s *storage.JournalStore) ([]byte, error) {
	ready, err := s.Initialized(ctx)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(c.DataDir, "master.key")
	if _, err = os.Stat(keyPath); err != nil {
		pending, pendingErr := s.HasSetup(ctx)
		if pendingErr != nil {
			return nil, pendingErr
		}
		if ready || pending || !os.IsNotExist(err) {
			return nil, fmt.Errorf("主密钥不可用，必须从备份恢复: %w", err)
		}
	}
	key, err := auth.LoadKey(keyPath)
	if err != nil {
		return nil, err
	}
	if ready {
		return key, nil
	}
	port := c.ControlPort + 2
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	done := make(chan struct{}, 1)
	service := bootstrap.New(s, key)
	server := &http.Server{Handler: service.Handler(port, func() {
		select {
		case done <- struct{}{}:
		default:
		}
	}), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	errorsCh := make(chan error, 1)
	go func() { errorsCh <- server.Serve(listener) }()
	log.Printf("管理员待绑定：仅本机 http://127.0.0.1:%d；请在交互终端执行 proxyctl setup-token --config <部署配置>，然后通过SSH隧道进入", port)
	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case result = <-errorsCh:
	case <-done:
	}
	drain, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(drain); err != nil {
		server.Close()
		if result == nil {
			result = err
		}
	}
	if result != nil && !errors.Is(result, http.ErrServerClosed) {
		return nil, result
	}
	ready, err = s.Initialized(ctx)
	if err != nil {
		return nil, err
	}
	if !ready {
		return nil, errors.New("首次绑定未完成")
	}
	return key, nil
}

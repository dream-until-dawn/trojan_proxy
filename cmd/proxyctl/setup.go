package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"golang.org/x/term"
)

// issueSetupToken 只在交互终端显示一次令牌，避免管道、普通容器日志和URL泄漏。
func issueSetupToken(path string) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("请使用交互终端（docker compose exec -it control proxyctl setup-token --config …），令牌不得重定向到日志")
	}
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	ctx := context.Background()
	s, err := storage.OpenJournal(ctx, filepath.Join(c.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		return err
	}
	defer s.Close()
	ready, err := s.Initialized(ctx)
	if err != nil {
		return err
	}
	if ready {
		return storage.ErrSetupState
	}
	keyPath := filepath.Join(c.DataDir, "master.key")
	if _, err = os.Stat(keyPath); err != nil {
		pending, e := s.HasSetup(ctx)
		if e != nil {
			return e
		}
		if pending || !os.IsNotExist(err) {
			return fmt.Errorf("主密钥不可用，请先恢复原主密钥")
		}
	}
	if _, err = auth.LoadKey(keyPath); err != nil {
		return err
	}
	token, err := auth.RandomToken()
	if err != nil {
		return err
	}
	if err = s.IssueSetup(ctx, auth.TokenHash(token), time.Now().Add(10*time.Minute)); err != nil {
		return err
	}
	port := c.ControlPort + 2
	fmt.Fprintln(os.Stdout, "一次性初始化令牌（10分钟有效，勿分享）：", token)
	fmt.Fprintf(os.Stdout, "在自己的电脑建立隧道：ssh -L %d:127.0.0.1:%d -L %d:127.0.0.1:%d <用户@服务器>\n然后访问 http://127.0.0.1:%d ，在网页填写令牌。\n", port, port, c.ControlPort, c.ControlPort, port)
	return nil
}

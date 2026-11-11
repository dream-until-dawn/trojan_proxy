package main

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/maintenance"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"golang.org/x/term"
)

// initializeAdmin 仅用于操作者交互终端，不经Web创建首个管理员。
func initializeAdmin(configPath string) error {
	c, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return fmt.Errorf("请在交互终端运行管理员初始化")
	}
	lock, err := maintenance.Acquire(c.DataDir, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = os.MkdirAll(c.DataDir, 0700); err != nil {
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
	if ready {
		return fmt.Errorf("管理员已存在，拒绝覆盖")
	}
	key, err := auth.LoadKey(filepath.Join(c.DataDir, "master.key"))
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "输入管理员强口令（至少16字节，不回显）: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "再次输入口令: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if string(first) != string(second) {
		return fmt.Errorf("两次口令不一致")
	}
	hash, err := auth.HashPassword(string(first))
	if err != nil {
		return err
	}
	clear(first)
	clear(second)
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return err
	}
	label := c.Domain
	if label == "" {
		label = "localhost"
	}
	uri := "otpauth://totp/" + url.PathEscape("Trojan Proxy:"+label) + "?secret=" + secret + "&issuer=Trojan%20Proxy&algorithm=SHA1&digits=6&period=30"
	fmt.Fprintln(os.Stdout, "请在自己的验证器中添加账户，类型TOTP，6位，30秒。以下秘密不要分享：")
	fmt.Fprintln(os.Stdout, "账户:", label, "\n设置密钥:", secret, "\n绑定URI:", uri)
	fmt.Fprint(os.Stderr, "输入验证器当前六位验证码以完成绑定: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	counter, ok := auth.VerifyTOTP(secret, strings.TrimSpace(line), time.Now(), -1)
	if !ok {
		return fmt.Errorf("验证码错误；账户未保存，请重试初始化")
	}
	encrypted, err := auth.EncryptSecret(key, secret)
	if err != nil {
		return err
	}
	var codes, hashes []string
	for range 8 {
		token, err := auth.RandomToken()
		if err != nil {
			return err
		}
		token = token[:24]
		codes = append(codes, token)
		hashes = append(hashes, auth.TokenHash(token))
	}
	if err = s.CreateAccount(context.Background(), storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: counter, Recovery: hashes}); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "管理员已建立。以下恢复码每个只能用一次，请离线保存；以后不会再次显示：")
	for _, code := range codes {
		fmt.Fprintln(os.Stdout, code)
	}
	fmt.Fprintln(os.Stdout, "绑定验证码已消费，首次登录请等待验证器下一次更新。")
	return nil
}

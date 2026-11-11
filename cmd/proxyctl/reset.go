package main

import (
	"bufio"
	"context"
	"errors"
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
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"golang.org/x/term"
)

// resetAdministrator 只允许SSH交互终端；独占锁保证不存在继续持有旧会话的控制进程。
func resetAdministrator(path string) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("管理员恢复必须在SSH交互终端完成，不允许管道或日志重定向")
	}
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	lock, err := maintenance.Acquire(c.DataDir, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	keyPath := filepath.Join(c.DataDir, "master.key")
	if _, err = os.Stat(keyPath); err != nil {
		return errors.New("主密钥缺失，必须先从私有备份恢复，不能重新生成")
	}
	key, err := auth.LoadKey(keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	ctx := context.Background()
	db, err := storage.OpenJournal(ctx, filepath.Join(c.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		return err
	}
	defer db.Close()
	ready, err := db.Initialized(ctx)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("没有现有管理员，请使用首次设置向导")
	}
	fmt.Fprint(os.Stderr, "输入新的强口令（至少16字节，不回显）: ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	defer clear(first)
	fmt.Fprint(os.Stderr, "再次输入新口令: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	defer clear(second)
	if string(first) != string(second) {
		return errors.New("两次口令不一致，未改变管理员")
	}
	hash, err := auth.HashPassword(string(first))
	if err != nil {
		return err
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		return err
	}
	label := c.Domain
	if journal, err := db.Load(ctx); err == nil && journal.Applied.Settings != "" {
		if document, err := settings.Decode(journal.Applied.Settings, c); err == nil {
			label = document.Site.Domain
		}
	}
	if label == "" {
		label = "localhost"
	}
	uri := "otpauth://totp/" + url.PathEscape("Trojan Proxy:"+label) + "?secret=" + secret + "&issuer=Trojan%20Proxy&algorithm=SHA1&digits=6&period=30"
	fmt.Fprintln(os.Stdout, "请在自己的验证器中创建新的TOTP账户（6位，30秒），旧验证器密钥将失效。")
	fmt.Fprintln(os.Stdout, "账户:", label, "\n设置密钥:", secret, "\n绑定URI:", uri)
	fmt.Fprint(os.Stderr, "输入新验证器的当前六位验证码: ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	counter, ok := auth.VerifyTOTP(secret, strings.TrimSpace(line), time.Now(), -1)
	if !ok {
		return errors.New("新验证码无效，未改变管理员")
	}
	encrypted, err := auth.EncryptSecret(key, secret)
	if err != nil {
		return err
	}
	codes, hashes := []string{}, []string{}
	for range 8 {
		code, err := auth.RandomToken()
		if err != nil {
			return err
		}
		codes = append(codes, code)
		hashes = append(hashes, auth.TokenHash(code))
	}
	fmt.Fprintln(os.Stdout, "新恢复码仅显示这一次，请离线保存：")
	for _, code := range codes {
		fmt.Fprintln(os.Stdout, code)
	}
	fmt.Fprint(os.Stderr, "确认已保存恢复码，并核实此主机域名、自身IP及目录挂载（输入yes提交，其余取消）: ")
	line, err = reader.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "yes" {
		return errors.New("已取消，未改变管理员")
	}
	if err = db.ResetAccount(ctx, storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: counter, Recovery: hashes}); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(c.DataDir, "recovery-required")); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Fprintln(os.Stdout, "管理员已重新绑定；主密钥、VPN口令和业务规则保留。请启动control，并使用下一组验证码登录。")
	return nil
}

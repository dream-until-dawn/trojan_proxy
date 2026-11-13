// proxyctl 提供部署诊断、一次令牌及仅限SSH终端的鉴权恢复工具。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"context"
	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/deployment"
	"github.com/dream-until-dawn/trojan_proxy/internal/ports"
	"github.com/dream-until-dawn/trojan_proxy/internal/recovery"
	"path/filepath"
)

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: proxyctl init|doctor|setup-token|backup|restore|admin-reset|downgrade-http-format|downgrade-format --config <配置文件>")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	defaultPath := "proxy.json"
	if args[0] == "setup-token" || args[0] == "prepare" || args[0] == "admin-reset" || args[0] == "backup" || args[0] == "restore" || args[0] == "downgrade-http-format" || args[0] == "downgrade-format" {
		defaultPath = "/etc/trojan-proxy/proxy.json"
	}
	path := flags.String("config", defaultPath, "部署配置文件")
	domain := flags.String("domain", "", "域名；留空为HTTP-only")
	admin := flags.Int("admin-port", 8007, "后台端口")
	data := flags.String("data-dir", "./data", "数据目录")
	certificate := flags.String("certificate", "/certs/fullchain.cer", "本地证书链路径，仅证书检查命令使用")
	privateKey := flags.String("private-key", "/certs/private.key", "本地私钥路径，仅证书检查命令使用")
	output := flags.String("output", "", "私有备份归档输出位置")
	archive := flags.String("archive", "", "冷还原归档路径")
	digest := flags.String("sha256", "", "从归档之外可信记录取得的SHA256")
	targetVersion := flags.Int("target-version", 0, "离线兼容回退的明确目标版本2、3、4或5")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("存在未知位置参数")
	}
	switch args[0] {
	case "downgrade-format":
		if *targetVersion < 2 || *targetVersion > 5 {
			return fmt.Errorf("请明确指定 --target-version 2、3、4或5")
		}
		return downgradeFormat(*path, *targetVersion)
	case "downgrade-http-format":
		return downgradeHTTPFormat(*path)
	case "admin-reset":
		return resetAdministrator(*path)
	case "backup":
		c, err := config.Load(*path)
		if err != nil {
			return err
		}
		target := *output
		if target == "" {
			target = filepath.Join(c.DataDir, "backups", "proxy-"+time.Now().UTC().Format("20060102T150405Z")+".tgz")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		report, err := recovery.Backup(ctx, c, target)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	case "restore":
		c, err := config.Load(*path)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err = recovery.Restore(ctx, c, *archive, *digest); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "冷还原完成，旧管理凭据已锁定；请先交互运行admin-reset，核实主机域名/IP/目录挂载，再启动control")
		return nil
	case "prepare":
		c, err := config.Load(*path)
		if err != nil {
			return err
		}
		if c.DataDir != "/data" {
			return fmt.Errorf("预制部署的数据卷必须挂载到/data；自定义部署请使用独立预检")
		}
		if err = deployment.Prepare(context.Background(), c, deployment.Defaults(c.DataDir)); err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, "专用卷和80/443预检通过，可以启动服务")
		return nil
	case "setup-token":
		return issueSetupToken(*path)
	case "certificate-check":
		c, err := config.Load(*path)
		if err != nil {
			return err
		}
		pair, err := certificates.ReadPairFiles(*certificate, *privateKey, c.Domain, time.Now(), nil)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(pair.Metadata())
	case "admin-init":
		return initializeAdmin(*path)
	case "init":
		c := config.Config{Version: 1, Domain: *domain, AdminPort: *admin, ControlPort: 18090, VPNPort: 18443, DataDir: *data}
		if err := c.Validate(); err != nil {
			return err
		}
		body, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("初始化不覆盖已有配置: %w", err)
		}
		_, writeErr := f.Write(append(body, '\n'))
		if writeErr == nil {
			writeErr = f.Sync()
		}
		closeErr := f.Close()
		if writeErr != nil {
			os.Remove(*path)
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Fprintln(os.Stdout, "配置已创建；尚未启动服务，下一步执行 doctor")
		return nil
	case "doctor":
		c, err := config.Load(*path)
		if err != nil {
			return err
		}
		// 这里只检查部署规划中的所有监听；运行实例的归属识别尚未接入。
		if err = ports.Check([]int{80, 443, c.AdminPort, c.ControlPort, c.ControlPort + 1, c.ControlPort + 2, c.VPNPort}); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"config_valid": true, "tcp_ports_available": true, "domain": c.Domain, "admin_port": c.AdminPort, "limitations": "未验证Docker版本、云防火墙或公网连通；预检不保留端口"})
	default:
		return fmt.Errorf("未知命令: %s", args[0])
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

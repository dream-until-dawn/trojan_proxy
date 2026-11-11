// proxyctl 提供初始化与只读部署诊断；业务凭据初始化在认证模块完成后接入。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/ports"
)

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: proxyctl init|doctor --config <配置文件>")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := flags.String("config", "proxy.json", "部署配置文件")
	domain := flags.String("domain", "", "域名；留空为HTTP-only")
	admin := flags.Int("admin-port", 8007, "后台端口")
	data := flags.String("data-dir", "./data", "数据目录")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("存在未知位置参数")
	}
	switch args[0] {
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
		if err = ports.Check([]int{80, 443, c.AdminPort, c.ControlPort, c.VPNPort}); err != nil {
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

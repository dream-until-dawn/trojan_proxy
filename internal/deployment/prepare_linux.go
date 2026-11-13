//go:build linux

package deployment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/ports"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

const markerName = ".trojan-proxy-volume"

type volume struct {
	path, role string
	uid        int
	mode       os.FileMode
}

func ensureVolume(v volume) error {
	if err := os.MkdirAll(v.path, v.mode); err != nil {
		return err
	}
	info, err := os.Lstat(v.path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("专用卷路径不是普通目录")
	}
	marker := filepath.Join(v.path, markerName)
	file, err := os.OpenFile(marker, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		root, err := os.Open(v.path)
		if err != nil {
			return err
		}
		entries, readErr := root.ReadDir(1)
		root.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if len(entries) != 0 {
			return fmt.Errorf("%s卷非空且未标记，拒绝接管", v.role)
		}
		file, err = os.OpenFile(marker, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0640)
		if err != nil {
			return err
		}
		_, err = file.WriteString("trojan-proxy-volume-v1\n" + v.role + "\n")
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = os.Chown(marker, v.uid, 10001); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else {
		body, readErr := io.ReadAll(io.LimitReader(file, 513))
		fileInfo, statErr := file.Stat()
		file.Close()
		if readErr != nil || statErr != nil || !fileInfo.Mode().IsRegular() || string(body) != "trojan-proxy-volume-v1\n"+v.role+"\n" {
			return fmt.Errorf("%s卷标记无效", v.role)
		}
	}
	// 仅修改已核实专用卷自身，不递归接管其中的文件或宿主机其他路径。
	if err = os.Chmod(v.path, v.mode); err != nil {
		return err
	}
	return os.Chown(v.path, v.uid, 10001)
}

func ownsIngress(ctx context.Context, socket string) bool {
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return false
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 10001 || owner.Gid != 10001 {
		return false
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	body, err := gateway.NewClient(socket).Current(bounded)
	if err != nil {
		return false
	}
	var actual struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct{ Listen []string }
			}
		}
	}
	if json.Unmarshal([]byte(body), &actual) != nil {
		return false
	}
	for name, address := range map[string]string{"public_80": ":80", "public_443": ":443"} {
		found := false
		for _, listen := range actual.Apps.HTTP.Servers[name].Listen {
			found = found || listen == address
		}
		if !found {
			return false
		}
	}
	return true
}

// Prepare 先检查80/443冲突，已运行实例必须证明受信任网关实际持有两个入口。
// 此命令由短生命周期root初始化容器执行，服务进程本身保持非root。
func Prepare(ctx context.Context, c config.Config, paths Paths) error {
	if os.Geteuid() != 0 {
		return errors.New("请由部署初始化容器准备专用卷")
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if !c.StandardIngress {
		return errors.New("部署未授权标准80/443入口")
	}
	seen := map[string]bool{}
	for _, p := range []string{paths.Data, paths.GatewayRun, paths.VPNRun, paths.Certificates, paths.CaddyData} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || seen[p] {
			return errors.New("专用卷必须使用互不重复的规范绝对路径")
		}
		for _, critical := range []string{"/", "/etc", "/var", "/run", "/tmp", "/usr", "/home", "/root", "/proc", "/sys", "/dev"} {
			if p == critical {
				return errors.New("拒绝将系统根目录作为专用卷")
			}
		}
		seen[p] = true
	}
	socket := filepath.Join(paths.GatewayRun, "admin.sock")
	owned := ownsIngress(ctx, socket)
	if !owned {
		if err := ports.Check([]int{80, 443, c.ControlPort, c.ControlPort + 1, c.ControlPort + 2}); err != nil {
			return fmt.Errorf("启动预检失败，未启动业务；请处理端口占用：%w", err)
		}
	}
	for _, v := range []volume{{paths.Data, "control-data", 10001, 0700}, {paths.GatewayRun, "gateway-run", 10001, 0770}, {paths.VPNRun, "vpn-run", 10002, 0770}, {paths.Certificates, "certificates", 10001, 0750}, {paths.CaddyData, "caddy-data", 10001, 0700}} {
		if err := ensureVolume(v); err != nil {
			return err
		}
	}
	if owned {
		return nil
	}
	settings := gateway.Settings{AccessLog: true, AdminPort: c.AdminPort, ControlPort: c.ControlPort, FilePort: c.ControlPort + 1, Socket: socket, Policy: routes.Policy{AdminPort: c.AdminPort, ControlPort: c.ControlPort, FilePort: c.ControlPort + 1, VPNPort: c.VPNPort, AllowStandardPorts: true}, Ingress: &gateway.Ingress{Mode: "reserved"}}
	body, err := gateway.Compile(settings, nil)
	if err != nil {
		return err
	}
	target := filepath.Join(paths.GatewayRun, "bootstrap.json")
	if info, err := os.Lstat(target); err == nil && !info.Mode().IsRegular() {
		return errors.New("网关启动快照不是普通文件")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.CreateTemp(paths.GatewayRun, ".bootstrap-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	_, err = file.WriteString(body)
	if err == nil {
		err = file.Chmod(0640)
	}
	if err == nil {
		err = file.Chown(10001, 10001)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, target)
}

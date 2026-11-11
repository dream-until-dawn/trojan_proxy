// Package config 定义部署配置及其静态约束；不包含管理员或 VPN 明文密码。
package config

import (
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path"
	"regexp"
	"strings"
)

// Config 是版本化部署配置，运行秘密另存于受限数据目录。
type Config struct {
	Version           int               `json:"version"`
	Domain            string            `json:"domain"`
	AdminPort         int               `json:"admin_port"`
	ControlPort       int               `json:"control_port"`
	VPNPort           int               `json:"vpn_port"`
	DataDir           string            `json:"data_dir"`
	PublicDirectories map[string]string `json:"public_directories,omitempty"`
	VPNManagement     bool              `json:"vpn_management,omitempty"`
	VPNAddresses      []string          `json:"vpn_own_addresses,omitempty"`
	VPNResolver       string            `json:"vpn_resolver,omitempty"`
	StandardIngress   bool              `json:"standard_ingress,omitempty"` // 部署授权接管80/443并启用持久业务设置。
}

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate 拒绝未知版本、端口重复与非法域名；空域名表示 HTTP-only 模式。
func (c Config) Validate() error {
	if c.Version != 1 {
		return errors.New("配置版本必须为1")
	}
	if c.VPNManagement && (len(c.VPNAddresses) == 0 || len(c.VPNAddresses) > 64) {
		return errors.New("VPN管理必须明确服务器自身IP地址，最多64个")
	}
	for _, value := range c.VPNAddresses {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return errors.New("VPN服务器自身IP格式错误")
		}
	}
	if c.VPNResolver != "" {
		resolver, err := netip.ParseAddrPort(c.VPNResolver)
		if err != nil || resolver.Port() == 0 || resolver.Addr().Zone() != "" {
			return errors.New("VPN解析器必须使用IP:端口")
		}
	}
	if strings.TrimSpace(c.DataDir) == "" {
		return errors.New("必须指定数据目录")
	}
	if c.ControlPort >= 65534 {
		return errors.New("内控端口必须为文件和首次绑定服务保留后两个端口")
	}
	for id, directory := range c.PublicDirectories {
		if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`).MatchString(id) || !strings.HasPrefix(directory, "/srv/public/") || path.Clean(directory) != directory {
			return errors.New("公开目录必须使用有效ID及/srv/public/内的独立挂载路径")
		}
	}
	ports := map[int]bool{80: true, 443: true, c.ControlPort + 1: true, c.ControlPort + 2: true}
	for _, port := range []int{c.AdminPort, c.ControlPort, c.VPNPort} {
		if port < 1024 || port > 65535 {
			return errors.New("后台、内控和VPN端口必须在1024至65535之间")
		}
		if ports[port] {
			return errors.New("监听端口重复或占用保留端口")
		}
		ports[port] = true
	}
	if c.Domain != "" {
		if len(c.Domain) > 253 || !strings.Contains(c.Domain, ".") {
			return errors.New("域名格式无效")
		}
		for _, label := range strings.Split(c.Domain, ".") {
			if !domainLabel.MatchString(label) {
				return errors.New("域名必须使用小写ASCII或Punycode，不带协议、路径或端口")
			}
		}
	}
	return nil
}

// Load 严格读取单个 JSON 文档，拒绝拼写错误字段和超大配置。
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return Config{}, err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 1024*1024 {
		return Config{}, errors.New("配置必须为不超过1MiB的普通文件")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 1024*1024))
	decoder.DisallowUnknownFields()
	var c Config
	if err = decoder.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return c, errors.New("配置只能包含一个JSON对象")
	}
	return c, c.Validate()
}

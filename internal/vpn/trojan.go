// Package vpn 提供结构化协议适配，不接受Web输入的原始引擎配置。
package vpn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Capabilities 明确后续协议需要提供的功能，避免控制层依赖引擎细节。
type Capabilities struct {
	Protocol    string `json:"protocol"`
	TCP         bool   `json:"tcp"`
	UDP         bool   `json:"udp"`
	Certificate bool   `json:"certificate"`
	ClashExport bool   `json:"clash_export"`
}

// TrojanCapabilities 是首版启用的协议能力。
func TrojanCapabilities() Capabilities {
	return Capabilities{Protocol: "trojan", TCP: true, UDP: true, Certificate: true, ClashExport: true}
}

// Settings 保存部署底线；有运行快照时，合并可变参数但保留保护端口和自身地址。
type Settings struct {
	Domain        string
	Port          int
	OwnAddresses  []netip.Addr
	Resolver      netip.AddrPort
	ReservedPorts []int
}

// Desired 的密码只参与内存配置生成和受控导出，普通JSON状态不包含它。
type Desired struct {
	Enabled            bool     `json:"enabled"`
	Password           string   `json:"-"`
	CertificateVersion string   `json:"certificate_version"`
	Profile            *Profile `json:"-"`
}

var certificateVersion = regexp.MustCompile(`^[0-9a-f]{64}$`)
var passwordFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
var domainFormat = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NewPassword 产生256位随机密码，不复用管理员口令。
func NewPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validate(s Settings, d Desired) error {
	if s.Port < 1024 || s.Port > 65535 || s.Domain == "" || len(s.Domain) > 253 || !strings.Contains(s.Domain, ".") {
		return errors.New("VPN端口或授权域名无效")
	}
	for _, label := range strings.Split(s.Domain, ".") {
		if !domainFormat.MatchString(label) {
			return errors.New("VPN域名必须是小写ASCII普通域名")
		}
	}
	if !passwordFormat.MatchString(d.Password) {
		return errors.New("VPN密码必须是32至128字符的随机URL安全字符")
	}
	if !certificateVersion.MatchString(d.CertificateVersion) {
		return errors.New("VPN必须引用已校验发布的证书版本")
	}
	if len(s.OwnAddresses) == 0 || len(s.OwnAddresses) > 64 {
		return errors.New("必须明确服务器自身IP地址")
	}
	for _, address := range s.OwnAddresses {
		if !address.IsValid() || address.Zone() != "" {
			return errors.New("服务器自身地址无效")
		}
	}
	if !s.Resolver.IsValid() || s.Resolver.Port() == 0 || s.Resolver.Addr().Zone() != "" {
		return errors.New("必须指定有效IP形式的DNS解析器")
	}
	return nil
}

// CompileTrojan 渲染固定sing-box版本配置；空字符串明确表示停止VPN。
func CompileTrojan(s Settings, d Desired) (string, error) {
	if !d.Enabled {
		return "", nil
	}
	var err error
	s, err = EffectiveSettings(s, d)
	if err != nil {
		return "", err
	}
	if err := validate(s, d); err != nil {
		return "", err
	}
	blocked := []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/3", "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"}
	for _, address := range s.OwnAddresses {
		address = address.Unmap()
		bits := 128
		if address.Is4() {
			bits = 32
		}
		blocked = append(blocked, netip.PrefixFrom(address, bits).String())
	}
	sort.Strings(blocked)
	versionRoot := "/certificates/" + d.CertificateVersion + "/"
	config := map[string]any{
		"log":       map[string]any{"level": "error", "timestamp": true},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "public-dns", "server": s.Resolver.Addr().String(), "server_port": s.Resolver.Port()}}, "disable_cache": true},
		"inbounds":  []any{map[string]any{"type": "trojan", "tag": "trojan-in", "listen": "::", "listen_port": s.Port, "users": []any{map[string]any{"name": "owner", "password": d.Password}}, "tls": map[string]any{"enabled": true, "certificate_path": versionRoot + "fullchain.pem", "key_path": versionRoot + "private.key", "min_version": "1.2"}}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "public", "connect_timeout": "10s"}},
		"route": map[string]any{"default_domain_resolver": "public-dns", "final": "public", "rules": []any{
			map[string]any{"domain_suffix": []string{"localhost", "local", "internal"}, "action": "reject"},
			// 先解析再判断目标，避免域名指向元数据/内网时绕过IP限制。
			map[string]any{"action": "resolve", "server": "public-dns", "disable_cache": true, "timeout": "5s"},
			map[string]any{"ip_cidr": blocked, "action": "reject"},
		}},
	}
	body, err := json.Marshal(config)
	return string(body), err
}

// ExportClash 返回完整JSON（合法YAML子集）；只在近期MFA保护的下载接口调用。
func ExportClash(s Settings, d Desired) ([]byte, error) {
	if !d.Enabled {
		return nil, errors.New("VPN未启用")
	}
	var err error
	s, err = EffectiveSettings(s, d)
	if err != nil {
		return nil, err
	}
	if err := validate(s, d); err != nil {
		return nil, err
	}
	config := map[string]any{"mixed-port": 7890, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule",
		"proxies": []any{map[string]any{"name": "独用Trojan", "type": "trojan", "server": s.Domain, "port": s.Port, "password": d.Password, "sni": s.Domain, "skip-cert-verify": false, "udp": true}},
		"rules":   []string{"DOMAIN," + s.Domain + ",DIRECT", "MATCH,独用Trojan"}}
	return json.MarshalIndent(config, "", "  ")
}

package vpn

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func fixture() (Settings, Desired) {
	return Settings{Domain: "vpn.example", Port: 18443, OwnAddresses: []netip.Addr{netip.MustParseAddr("47.82.112.245")}, Resolver: netip.MustParseAddrPort("9.9.9.9:53")}, Desired{Enabled: true, Password: strings.Repeat("x", 43), CertificateVersion: strings.Repeat("a", 64)}
}

func TestCompileAndExport(t *testing.T) {
	s, d := fixture()
	body, err := CompileTrojan(s, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"type":"trojan"`, `"listen":"::"`, `47.82.112.245/32`, `100.64.0.0/10`, `"action":"resolve"`, `"action":"reject"`, `"disable_cache":true`} {
		if !strings.Contains(body, required) {
			t.Fatal("缺少协议或目的地址保护", required)
		}
	}
	if strings.Index(body, `"action":"resolve"`) > strings.Index(body, `"ip_cidr"`) {
		t.Fatal("解析发生在IP检查后")
	}
	state, err := json.Marshal(d)
	if err != nil || strings.Contains(string(state), d.Password) {
		t.Fatal("普通状态包含密码", err)
	}
	profile, err := ExportClash(s, d)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`"skip-cert-verify": false`, `"allow-lan": false`, `"udp": true`, "DOMAIN,vpn.example,DIRECT", d.Password} {
		if !strings.Contains(string(profile), required) {
			t.Fatal("导出缺少安全设置", required)
		}
	}
	d.Enabled = false
	if body, err = CompileTrojan(Settings{}, d); err != nil || body != "" {
		t.Fatal("停止VPN依赖证书或域名", err)
	}
	if _, err = ExportClash(s, d); err == nil {
		t.Fatal("停止状态仍可导出")
	}
}

func TestRejectInvalidDesired(t *testing.T) {
	for _, name := range []string{"password", "version", "port", "domain", "own-address", "resolver"} {
		t.Run(name, func(t *testing.T) {
			s, d := fixture()
			switch name {
			case "password":
				d.Password = "weak"
			case "version":
				d.CertificateVersion = "../../secret"
			case "port":
				s.Port = 443
			case "domain":
				s.Domain = "*.example"
			case "own-address":
				s.OwnAddresses = nil
			case "resolver":
				s.Resolver = netip.AddrPort{}
			}
			if _, err := CompileTrojan(s, d); err == nil {
				t.Fatal("非法VPN配置未拒绝")
			}
		})
	}
}

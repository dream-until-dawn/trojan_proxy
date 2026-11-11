package config

import (
	"os"
	"path/filepath"
	"testing"
)

func valid() Config {
	return Config{Version: 1, Domain: "qin-xin.top", AdminPort: 8007, ControlPort: 18090, VPNPort: 18443, DataDir: "data"}
}
func TestValidate(t *testing.T) {
	c := valid()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"https://qin-xin.top", "example.com:8007", "a..com", "-a.example", "a_.com", "example.com/", "A.com"} {
		c = valid()
		c.Domain = domain
		if c.Validate() == nil {
			t.Fatalf("未拒绝域名: %s", domain)
		}
	}
	for _, port := range []int{-1, 80, 443, 18090, 18091, 18092, 65536} {
		c = valid()
		c.AdminPort = port
		if c.Validate() == nil {
			t.Fatalf("未拒绝端口: %d", port)
		}
	}
	c = valid()
	c.Domain = ""
	if err := c.Validate(); err != nil {
		t.Fatal("空域名应允许HTTP模式", err)
	}
}
func TestStrictJSON(t *testing.T) {
	for _, body := range []string{`{"typo":1}`, `{} {}`, `{"version":999}`} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("未拒绝配置: %s", body)
		}
	}
}

func TestVPNDeploymentBoundary(t *testing.T) {
	c := valid()
	c.VPNManagement = true
	if c.Validate() == nil {
		t.Fatal("VPN缺少自身IP仍可启用管理")
	}
	c.VPNAddresses = []string{"47.82.112.245"}
	c.VPNResolver = "9.9.9.9:53"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, resolver := range []string{"localhost:53", "9.9.9.9:0", "https://dns.google/dns-query"} {
		c.VPNResolver = resolver
		if c.Validate() == nil {
			t.Fatal("非法解析器未拒绝", resolver)
		}
	}
	c.VPNResolver = ""
	c.VPNAddresses = []string{"fe80::1%eth0"}
	if c.Validate() == nil {
		t.Fatal("带zone的自身IP未拒绝")
	}
}

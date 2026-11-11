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
	for _, port := range []int{-1, 80, 443, 18090, 65536} {
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

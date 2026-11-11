package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
)

func TestInitDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	args := []string{"init", "--config", path, "--domain", "qin-xin.top"}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path)
	if err != nil || c.AdminPort != 8007 {
		t.Fatalf("初始化配置错误: %+v %v", c, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = run(args); err == nil {
		t.Fatal("未拒绝覆盖已有配置")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(before) != string(after) {
		t.Fatal("二次执行改变已有配置")
	}
}
func TestInvalidInitDoesNotCreateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxy.json")
	if err := run([]string{"init", "--config", path, "--admin-port", "443"}); err == nil {
		t.Fatal("非法端口初始化被接受")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("非法配置遗留文件")
	}
}

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestrictedEngineCommands(t *testing.T) {
	for _, args := range [][]string{nil, {"shell"}, {"run"}, {"check", "-c", "missing", "extra"}} {
		if err := run(args); err == nil {
			t.Fatal("错误命令未拒绝", args)
		}
	}
	for _, scenario := range []struct{ body, reason string }{
		{`{"experimental":{"clash_api":{"external_controller":":9090"}}}`, "非授权功能"},
		{`{"ntp":{"enabled":true,"server":"time.example"}}`, "非授权功能"},
		{`{"inbounds":[{"type":"socks","listen_port":1080}]}`, "未启用的模块"},
		{`{"outbounds":[{"type":"ssh","server":"example"}]}`, "未启用的模块"},
		{`{"dns":{"servers":[{"type":"https","server":"example"}]}}`, "未启用的模块"},
	} {
		path := filepath.Join(t.TempDir(), "engine.json")
		if err := os.WriteFile(path, []byte(scenario.body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := run([]string{"check", "-c", path}); err == nil || !strings.Contains(err.Error(), scenario.reason) {
			t.Fatal("受限模块拒绝原因不正确", scenario.body, err)
		}
	}
}

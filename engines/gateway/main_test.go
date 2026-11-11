package main

import (
	"github.com/caddyserver/caddy/v2"
	"testing"
)

func TestRequiredAndExcludedModules(t *testing.T) {
	for _, name := range []string{"http.handlers.reverse_proxy", "http.handlers.rewrite", "http.handlers.static_response", "tls.issuance.acme", "tls.issuance.internal"} {
		if _, err := caddy.GetModule(name); err != nil {
			t.Fatal("缺少产品依赖模块", name, err)
		}
	}
	for _, name := range []string{"http.handlers.templates", "http.handlers.file_server", "http.handlers.authentication", "http.encoders.zstd"} {
		if _, err := caddy.GetModule(name); err == nil {
			t.Fatal("意外引入非产品依赖模块", name)
		}
	}
}

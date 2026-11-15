// 本模块保持Caddy 2.11.9配置/缓存协议，只注册产品使用的网关功能。
package main

import (
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile" // Caddyfile适配。
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp"                     // HTTP与固定响应。
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"             // 受控头操作。
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"        // 回环上游。
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/rewrite"             // 路径前缀处理。
	_ "github.com/caddyserver/caddy/v2/modules/caddypki"                      // 隔离生命周期测试的内部CA。
	_ "github.com/caddyserver/caddy/v2/modules/caddytls"                      // TLS、自动ACME与证书缓存。
	_ "github.com/caddyserver/caddy/v2/modules/logging"                       // 访问日志落盘前脱敏与有界轮转。
	_ "github.com/dream-until-dawn/trojan_proxy/engines/gateway/trojanprefix" // 有界协议分类，不接触口令。
	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4proxy"
	_ "github.com/mholt/caddy-l4/modules/l4subroute"
	_ "github.com/mholt/caddy-l4/modules/l4tls"
)

func main() { caddycmd.Main() }

package gateway

import (
	"errors"
	"net"
	"strconv"
)

// SharedTrojan 只引用已授权的主站和原引擎端口，不能指定任意转发地址。
type SharedTrojan struct{ Port int }

func configureSharedTrojan(s Settings, servers map[string]any) error {
	if s.SharedTrojan == nil {
		return nil
	}
	if s.Ingress == nil || s.Domain == "" || !s.Policy.AllowStandardPorts || s.SharedTrojan.Port != s.Policy.VPNPort || s.SharedTrojan.Port < 1024 || s.SharedTrojan.Port > 65535 {
		return errors.New("共享443需要标准域名入口及受保护的VPN引擎端口")
	}
	// 证书未就绪时保留原申请入口，不开放VPN分支。
	if !ingressReady(s.Ingress) {
		return nil
	}
	server, ok := servers["public_443"].(map[string]any)
	if !ok {
		return errors.New("共享443缺少标准HTTPS服务")
	}
	policies, ok := server["tls_connection_policies"]
	if !ok {
		return errors.New("共享443缺少TLS连接策略")
	}
	tls := map[string]any{"server_name": s.Domain}
	if s.Ingress.Mode == "manual" {
		tls["root_ca_pem_files"] = []string{s.Ingress.Certificate}
	}
	proxy := map[string]any{"handler": "proxy", "upstreams": []any{map[string]any{"dial": []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(s.SharedTrojan.Port))}, "tls": tls}}}
	branch := map[string]any{"match": []any{map[string]any{"trojan_prefix": map[string]any{"sni": s.Domain}}}, "handle": []any{proxy}}
	// 同一连接交回HTTP，保留来源IP/TLS状态，不依赖公网转发头。
	server["listener_wrappers"] = []any{map[string]any{"wrapper": "layer4", "matching_timeout": int64(3e9), "routes": []any{
		map[string]any{"handle": []any{map[string]any{"handler": "tls", "handshake_timeout": int64(10e9), "connection_policies": policies}, map[string]any{"handler": "subroute", "matching_timeout": int64(3e9), "routes": []any{branch}}}},
	}}}
	delete(server, "tls_connection_policies") // listener已终止TLS，禁止二次握手。
	return nil
}

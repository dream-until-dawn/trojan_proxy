package gateway

import (
	"errors"
	"path"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// Ingress 只由部署工具设置。nil保留阶段性高端口后台，非nil固定占用80/443。
// 自动签发始终限定单个授权域名，不允许业务Host触发任意域名申请。
type Ingress struct {
	Mode             string // reserved（无域名）、automatic、manual。
	Certificate      string // manual时必须是不可变发布目录内的固定路径。
	Key              string
	AwaitCertificate bool // 仅automatic；由证书适配器推导，不接受网页就绪标志。
	ACMEEmail        string
}

func validateIngress(s Settings, rules []routes.Rule) error {
	for _, rule := range rules {
		if rule.HTTPS {
			if s.Domain == "" || !allowedHost(s, rule.Host) {
				return errors.New("HTTPS规则仅允许当前授权域名")
			}
			if rule.Host == s.Domain && s.Ingress != nil && (s.Ingress.AwaitCertificate || (s.Ingress.Mode != "automatic" && s.Ingress.Mode != "manual")) {
				return errors.New("HTTPS规则需要已就绪的可信证书")
			}
		}
	}
	if s.Ingress == nil {
		if len(s.Hosts) > 0 || s.AdminDomain != "" {
			return errors.New("多域名需要标准入口")
		}
		return nil
	}
	if err := validateHosts(s, rules); err != nil {
		return err
	}
	i := s.Ingress
	if i.AwaitCertificate && i.Mode != "automatic" {
		return errors.New("仅自动签发允许等待证书")
	}
	if !s.Policy.AllowStandardPorts {
		return errors.New("标准入口需要部署阶段明确授权接管80/443")
	}
	switch i.Mode {
	case "reserved":
		if s.Domain != "" || i.Certificate != "" || i.Key != "" {
			return errors.New("无域名模式不得指定域名或证书")
		}
	case "automatic", "manual", "unavailable":
		if s.Domain == "" {
			return errors.New("HTTPS入口需要授权域名")
		}
		// 复用规则层的域名语法校验，不接受通配符、URL或占位符。
		probe := routes.Rule{ID: "domain", Name: "域名校验", Port: 80, Host: s.Domain, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 65000}
		if err := routes.ValidateSet([]routes.Rule{probe}, routes.Policy{AllowStandardPorts: true}); err != nil {
			return err
		}
		if i.Mode == "manual" {
			for _, p := range []string{i.Certificate, i.Key} {
				if !strings.HasPrefix(p, "/certificates/") || path.Clean(p) != p || strings.ContainsAny(p, "{}\\\x00") {
					return errors.New("手工证书必须引用受控发布目录")
				}
			}
		} else if i.Certificate != "" || i.Key != "" {
			return errors.New("自动模式不能同时加载手工证书")
		}
	default:
		return errors.New("未知入口证书模式")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if r.Port != 80 && r.Port != 443 {
			continue
		}
		if i.Mode == "reserved" && r.Port == 443 {
			return errors.New("无域名模式443仅保留，不能发布规则")
		}
		if s.Domain != "" {
			if r.Host != "" && !allowedHost(s, r.Host) {
				return errors.New("标准HTTPS入口仅支持部署授权的域名")
			}
			key := r.Host + "|" + r.Path
			if r.Host == "" {
				key = s.Domain + "|" + r.Path
			}
			if seen[key] {
				return errors.New("80和443规则合并后路径重复")
			}
			seen[key] = true
		}
	}
	return nil
}

func configureIngress(s Settings, servers map[string]any, tlsApp map[string]any) error {
	if len(s.Hosts) > 0 {
		return configureHosts(s, servers, tlsApp)
	}
	// 不生成任何公网明文后台；无域名时只保留控制服务的SSH隧道入口。
	if s.Domain == "" {
		delete(servers, "admin")
		delete(tlsApp, "certificates")
		if servers["public_80"] == nil {
			welcome, err := welcomeRoute("")
			if err != nil {
				return err
			}
			servers["public_80"] = publicServer(":80", []any{welcome})
		}
		reserved := publicServer(":443", nil)
		reserved["tls_connection_policies"] = []any{map[string]any{"drop": true}}
		servers["public_443"] = reserved
		return nil
	}
	if servers["public_443"] == nil {
		welcome, err := welcomeForSettings(s)
		if err != nil {
			return err
		}
		servers["public_443"] = publicServer(":443", []any{welcome})
	}
	https := servers["public_443"].(map[string]any)
	https["tls_connection_policies"] = []any{map[string]any{}}
	// 标准HTTPS整体限制Host，避免空Host业务规则被其他域名复用。
	https["routes"] = []any{map[string]any{"match": []any{map[string]any{"host": []string{s.Domain}}}, "handle": []any{map[string]any{"handler": "subroute", "routes": https["routes"]}}, "terminal": true}, notFound()}
	if s.Ingress.AwaitCertificate || s.Ingress.Mode == "unavailable" {
		if servers["public_80"] == nil {
			welcome, err := welcomeForSettings(s)
			if err != nil {
				return err
			}
			servers["public_80"] = publicServer(":80", []any{welcome})
		}
		httpServer := servers["public_80"].(map[string]any)
		httpServer["routes"] = []any{map[string]any{"match": []any{map[string]any{"host": []string{s.Domain}}}, "handle": []any{map[string]any{"handler": "subroute", "routes": httpServer["routes"]}}, "terminal": true}, notFound()}
	} else {
		redirect := map[string]any{"match": []any{map[string]any{"host": []string{s.Domain}}}, "handle": []any{map[string]any{"handler": "static_response", "status_code": 308, "headers": map[string]any{"Location": []string{"https://" + s.Domain + "{http.request.uri}"}}}}, "terminal": true}
		servers["public_80"] = publicServer(":80", []any{redirect})
	}
	if s.Ingress.Mode == "unavailable" {
		delete(servers, "admin")
		delete(tlsApp, "certificates")
		delete(tlsApp, "automation")
		https["tls_connection_policies"] = []any{map[string]any{"drop": true}}
		return nil
	}
	if s.Ingress.Mode == "manual" {
		tlsApp["certificates"] = map[string]any{"load_files": []any{map[string]any{"certificate": s.Ingress.Certificate, "key": s.Ingress.Key}}}
		return nil
	}
	tlsApp["certificates"] = map[string]any{"automate": []string{s.Domain}}
	issuer := map[string]any{"module": "acme", "ca": "https://acme-v02.api.letsencrypt.org/directory", "challenges": map[string]any{"tls-alpn": map[string]any{"disabled": true}}}
	if s.Ingress.ACMEEmail != "" {
		issuer["email"] = s.Ingress.ACMEEmail
	}
	tlsApp["automation"] = map[string]any{"policies": []any{map[string]any{"subjects": []string{s.Domain}, "issuers": []any{issuer}}}}
	return nil
}

func notFound() any {
	return map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 404}}}
}

func publicServer(address string, rules []any) map[string]any {
	return map[string]any{"listen": []string{address}, "automatic_https": map[string]any{"disable": true}, "routes": append(rules, notFound())}
}

package gateway

import (
	"errors"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// Host 的证书状态由可信证书适配器生成，不接受HTTP传入就绪标志。
type Host struct {
	Name    string
	Ingress *Ingress
}

func additionalHost(s Settings, name string) (Host, bool) {
	for _, h := range s.Hosts {
		if h.Name == name {
			return h, true
		}
	}
	return Host{}, false
}
func allowedHost(s Settings, name string) bool {
	if name == s.Domain && name != "" {
		return true
	}
	_, ok := additionalHost(s, name)
	return ok
}
func ingressReady(i *Ingress) bool {
	return i != nil && !i.AwaitCertificate && (i.Mode == "automatic" || i.Mode == "manual")
}

func validateHosts(s Settings, ruleset []routes.Rule) error {
	if len(s.Hosts) > 20 {
		return errors.New("附加域名超过上限")
	}
	seen := map[string]bool{s.Domain: true}
	for _, h := range s.Hosts {
		if s.Domain == "" || h.Name == "" || !strings.HasSuffix(h.Name, "."+s.Domain) || seen[h.Name] || h.Ingress == nil || h.Ingress.Mode != "automatic" || h.Ingress.Certificate != "" || h.Ingress.Key != "" {
			return errors.New("附加域名或自动证书策略无效")
		}
		probe := routes.Rule{ID: "domain", Name: "域名校验", Port: 80, Host: h.Name, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 65000}
		if err := routes.ValidateSet([]routes.Rule{probe}, routes.Policy{AllowStandardPorts: true}); err != nil {
			return err
		}
		seen[h.Name] = true
	}
	if s.AdminDomain != "" {
		if s.AdminDomain == s.Domain || !seen[s.AdminDomain] || s.AdminPath != "" {
			return errors.New("独立后台域名未登记或与管理路径冲突")
		}
		for _, r := range ruleset {
			if r.Host == s.AdminDomain && (r.Port == 80 || r.Port == 443) {
				return errors.New("独立后台域名不能发布业务规则")
			}
		}
	}
	return nil
}

// configureHosts 不依赖通配符或按需签发；每个域名独立决定HTTP跳转和业务可用性。
func configureHosts(s Settings, servers, tlsApp map[string]any) error {
	if s.Ingress.Mode == "unavailable" {
		delete(servers, "admin")
	}
	hosts := append([]Host{{Name: s.Domain, Ingress: s.Ingress}}, s.Hosts...)
	existing, ok := servers["public_443"].(map[string]any)
	if !ok {
		existing = publicServer(":443", nil)
	}
	var ruleset []any
	for _, r := range existing["routes"].([]any) {
		if r.(map[string]any)["match"] != nil {
			ruleset = append(ruleset, r)
		}
	}
	names := []string{}
	tlsNames := []string{}
	automate := []string{}
	files := []any{}
	policies := []any{}
	httpRoutes := []any{}
	for _, h := range hosts {
		names = append(names, h.Name)
		ready := ingressReady(h.Ingress)
		if h.Ingress.Mode != "unavailable" {
			tlsNames = append(tlsNames, h.Name)
		}
		welcome, err := welcomeRouteWithReady(h.Name, ready)
		if err != nil {
			return err
		}
		fallback := welcome.(map[string]any)
		if !ready {
			fallback = map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 503}}, "terminal": true}
		}
		fallback["match"] = []any{map[string]any{"host": []string{h.Name}}}
		ruleset = append(ruleset, fallback)
		if ready {
			httpRoutes = append(httpRoutes, map[string]any{"match": []any{map[string]any{"host": []string{h.Name}}}, "handle": []any{map[string]any{"handler": "static_response", "status_code": 308, "headers": map[string]any{"Location": []string{"https://" + h.Name + "{http.request.uri}"}}}}, "terminal": true})
		} else {
			pending, err := welcomeRouteWithReady(h.Name, false)
			if err != nil {
				return err
			}
			route := pending.(map[string]any)
			route["match"] = []any{map[string]any{"host": []string{h.Name}}}
			httpRoutes = append(httpRoutes, route)
		}
		switch h.Ingress.Mode {
		case "automatic":
			automate = append(automate, h.Name)
			issuer := map[string]any{"module": "acme", "ca": "https://acme-v02.api.letsencrypt.org/directory", "challenges": map[string]any{"tls-alpn": map[string]any{"disabled": true}}}
			if h.Ingress.ACMEEmail != "" {
				issuer["email"] = h.Ingress.ACMEEmail
			}
			policies = append(policies, map[string]any{"subjects": []string{h.Name}, "issuers": []any{issuer}})
		case "manual":
			files = append(files, map[string]any{"certificate": h.Ingress.Certificate, "key": h.Ingress.Key})
		}
	}
	existing["routes"] = []any{map[string]any{"match": []any{map[string]any{"host": names}}, "handle": []any{map[string]any{"handler": "subroute", "routes": ruleset}}, "terminal": true}, notFound()}
	existing["tls_connection_policies"] = []any{map[string]any{"match": map[string]any{"sni": tlsNames}}, map[string]any{"drop": true}}
	servers["public_443"] = existing
	servers["public_80"] = publicServer(":80", httpRoutes)
	certificates := map[string]any{}
	if len(automate) > 0 {
		certificates["automate"] = automate
	}
	if len(files) > 0 {
		certificates["load_files"] = files
	}
	if len(certificates) > 0 {
		tlsApp["certificates"] = certificates
	} else {
		delete(tlsApp, "certificates")
	}
	if len(policies) > 0 {
		tlsApp["automation"] = map[string]any{"policies": policies}
	} else {
		delete(tlsApp, "automation")
	}
	return nil
}

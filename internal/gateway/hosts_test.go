package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

func hostSettings() Settings {
	return Settings{Domain: "example.test", AdminPath: "/proxy", AdminPort: 8007, ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", Ingress: &Ingress{Mode: "automatic"}, Hosts: []Host{{Name: "one.example.test", Ingress: &Ingress{Mode: "automatic"}}, {Name: "two.example.test", Ingress: &Ingress{Mode: "automatic", AwaitCertificate: true}}, {Name: "proxy.example.test", Ingress: &Ingress{Mode: "automatic"}}}, Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443, AllowStandardPorts: true}}
}
func hostRules() []routes.Rule {
	return []routes.Rule{{ID: "one", Name: "one", Port: 443, Host: "one.example.test", Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3030, HTTPS: true}, {ID: "two", Name: "two", Port: 443, Host: "two.example.test", Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3031, HTTPS: true}}
}
func TestHostIsolationAndPendingCertificate(t *testing.T) {
	s := hostSettings()
	body, err := Compile(s, hostRules())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "127.0.0.1:3030") || strings.Contains(body, "127.0.0.1:3031") {
		t.Fatal("unready host reached business upstream")
	}
	if !strings.Contains(body, `https://one.example.test{http.request.uri}`) || strings.Contains(body, `https://two.example.test{http.request.uri}`) {
		t.Fatal("per-host HTTPS readiness ignored")
	}
	var root map[string]any
	json.Unmarshal([]byte(body), &root)
	certs := root["apps"].(map[string]any)["tls"].(map[string]any)["certificates"].(map[string]any)["automate"].([]any)
	if len(certs) != 4 {
		t.Fatal("certificate allowlist incomplete", certs)
	}
	rules := hostRules()
	rules[0].Host = "unknown.example.test"
	if _, err = Compile(s, rules); err == nil {
		t.Fatal("unregistered HTTPS host accepted")
	}
	s.AdminDomain = "proxy.example.test"
	s.AdminPath = ""
	rules = hostRules()
	rules[0].Host = s.AdminDomain
	if _, err = Compile(s, rules); err == nil {
		t.Fatal("business captured administrator host")
	}
	s = hostSettings()
	s.Hosts = append(s.Hosts, s.Hosts[0])
	if _, err = Compile(s, nil); err == nil {
		t.Fatal("duplicate hostname accepted")
	}
}
func TestAdminHostTransitionPreservesOldBusinessAndBothOrigins(t *testing.T) {
	current := hostSettings()
	next := current
	next.AdminPath = ""
	next.AdminDomain = "proxy.example.test"
	body, err := CompileAdminTransition(current, next, hostRules())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"path":["/proxy","/proxy/*"]`) || !strings.Contains(body, `"host":["proxy.example.test"]`) || !strings.Contains(body, "127.0.0.1:3030") {
		t.Fatal("candidate replaced current routes")
	}
	confirmed, err := Compile(next, hostRules())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(confirmed, `"path":["/proxy","/proxy/*"]`) {
		t.Fatal("old administrator prefix survived confirmation")
	}
}

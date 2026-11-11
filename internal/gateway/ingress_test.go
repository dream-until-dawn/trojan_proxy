package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

func ingressSettings(domain, mode string) Settings {
	return Settings{Domain: domain, AdminPort: 8007, ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443, AllowStandardPorts: true}, Ingress: &Ingress{Mode: mode}}
}

func TestReservedIngressHasNoPublicAdminOrCertificate(t *testing.T) {
	body, err := Compile(ingressSettings("", "reserved"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`":80"`, `":443"`, `"drop":true`, `"protocols":["h1","h2"]`} {
		if !strings.Contains(body, required) {
			t.Fatalf("缺少无域名保护: %s", required)
		}
	}
	for _, forbidden := range []string{`":8007"`, `load_files`, `automate`, `18090`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("无域名暴露后台或证书: %s", forbidden)
		}
	}
}

func TestAutomaticIngressBindsDomainAndHTTPRedirect(t *testing.T) {
	s := ingressSettings("qin-xin.top", "automatic")
	r := routes.Rule{ID: "app", Name: "服务", Port: 80, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3000}
	body, err := Compile(s, []routes.Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct{ Routes []json.RawMessage }
			}
		}
	}
	if err = json.Unmarshal([]byte(body), &config); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config.Apps.HTTP.Servers["public_80"].Routes[0]), "3000") {
		t.Fatal("域名模式仍在HTTP承载业务")
	}
	if !strings.Contains(string(config.Apps.HTTP.Servers["public_443"].Routes[0]), "3000") {
		t.Fatal("80规则未迁移到HTTPS")
	}
	for _, required := range []string{`"automate":["qin-xin.top"]`, `"status_code":308`, `https://qin-xin.top{http.request.uri}`, `"tls-alpn":{"disabled":true}`} {
		if !strings.Contains(body, required) {
			t.Fatalf("缺少自动HTTPS设置: %s", required)
		}
	}
	if strings.Contains(body, "load_files") {
		t.Fatal("自动证书被手工证书覆盖")
	}
}

func TestIngressRejectsAmbiguousAndUnauthorizedRules(t *testing.T) {
	r := routes.Rule{ID: "app", Name: "服务", Port: 80, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3000}
	for _, scenario := range []string{"other-host", "duplicate", "reserved-443", "not-owned", "wrong-mode", "manual-path"} {
		t.Run(scenario, func(t *testing.T) {
			s := ingressSettings("qin-xin.top", "automatic")
			rs := []routes.Rule{r}
			switch scenario {
			case "other-host":
				rs[0].Host = "other.example"
			case "duplicate":
				second := r
				second.ID = "other"
				second.Port = 443
				rs = append(rs, second)
			case "reserved-443":
				s = ingressSettings("", "reserved")
				rs[0].Port = 443
			case "not-owned":
				s.Policy.AllowStandardPorts = false
			case "wrong-mode":
				s.Ingress.Mode = "reserved"
			case "manual-path":
				s.Ingress = &Ingress{Mode: "manual", Certificate: "/etc/shadow", Key: "/certificates/test/key"}
			}
			if _, err := Compile(s, rs); err == nil {
				t.Fatal("非法标准入口设置未被拒绝")
			}
		})
	}
}

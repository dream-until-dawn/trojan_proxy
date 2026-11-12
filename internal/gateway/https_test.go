package gateway

import (
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	"strings"
	"testing"
)

func TestCustomHTTPSRequiresAuthorizedReadyCertificate(t *testing.T) {
	s := ingressSettings("qin-xin.top", "automatic")
	r := routes.Rule{ID: "secure", Name: "HTTPS应用", Port: 8001, Host: s.Domain, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3030, HTTPS: true}
	body, err := Compile(s, []routes.Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"sni":["qin-xin.top"]`) || !strings.Contains(body, `"public_8001"`) {
		t.Fatal("custom HTTPS TLS policy missing")
	}
	for _, name := range []string{"unknown-domain", "empty-host", "await-certificate", "no-domain", "reserved", "unavailable", "mixed-port", "port80"} {
		t.Run(name, func(t *testing.T) {
			settings := s
			settings.Ingress = &Ingress{Mode: "automatic"}
			rule := r
			ruleset := []routes.Rule{rule}
			switch name {
			case "unknown-domain":
				ruleset[0].Host = "other.invalid"
			case "empty-host":
				ruleset[0].Host = ""
			case "await-certificate":
				settings.Ingress.AwaitCertificate = true
			case "no-domain":
				settings.Domain = ""
			case "reserved":
				settings.Domain = ""
				settings.Ingress.Mode = "reserved"
			case "unavailable":
				settings.Ingress.Mode = "unavailable"
			case "mixed-port":
				other := rule
				other.ID = "plain"
				other.Path = "/plain"
				other.HTTPS = false
				ruleset = append(ruleset, other)
			case "port80":
				ruleset[0].Port = 80
			}
			if _, err := Compile(settings, ruleset); err == nil {
				t.Fatal("unsafe HTTPS rule accepted", name)
			}
		})
	}
	r.HTTPS = false
	body, err = Compile(s, []routes.Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, `"sni"`) {
		t.Fatal("legacy HTTP route unexpectedly became HTTPS")
	}
}

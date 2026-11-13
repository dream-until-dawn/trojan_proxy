package site

import (
	"context"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
)

func TestAdminDomainNeedsOwnCertificateAndPreservesVPN(t *testing.T) {
	p, current, revision, _, _, _ := plannerFixture(t)
	p.View.Deployment.StandardIngress = true
	p.View.Standard = true
	p.View.Ingress = p.Ingress
	p.View.DomainIngress = p.DomainIngress
	next := current
	next.Domains = []string{"proxy.probe.test"}
	next.AdminDomain = "proxy.probe.test"
	next.AdminPath = ""
	if e := (settings.Document{Version: 1, Site: next}).Validate(p.View.Deployment); e != nil {
		t.Fatal(e)
	}
	if p.Ready(context.Background(), next) == nil {
		t.Fatal("primary certificate authorized administrator subdomain")
	}
	plan, e := p.Dual(context.Background(), current, next, revision)
	if e != nil {
		t.Fatal(e)
	}
	if plan.VPN != revision.VPN {
		t.Fatal("administrator hostname changed VPN command")
	}
}

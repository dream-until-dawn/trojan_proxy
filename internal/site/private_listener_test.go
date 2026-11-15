package site

import (
	"context"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
	"testing"
)

func TestPrivateListenerPlanPreservesGatewayAndCredential(t *testing.T) {
	p, current, revision, _, _, _ := plannerFixture(t)
	p.View.Deployment.StandardIngress = true
	current.SharedTrojan443 = true
	base, e := p.Steady(context.Background(), current, revision)
	if e != nil {
		t.Fatal(e)
	}
	revision.Gateway, revision.VPN, revision.GatewaySettings = base.Gateway, base.VPN, base.Fingerprint
	candidate := current
	candidate.VPNLoopbackOnly = true
	dual, e := p.Dual(context.Background(), current, candidate, revision)
	if e != nil {
		t.Fatal(e)
	}
	if dual.VPN != revision.VPN || dual.Gateway != revision.Gateway {
		t.Fatal("private candidate reloaded gateway or VPN")
	}
	steady, e := p.Steady(context.Background(), candidate, revision)
	if e != nil {
		t.Fatal(e)
	}
	if steady.Gateway != revision.Gateway || steady.Fingerprint != revision.GatewaySettings {
		t.Fatal("private change reloaded business gateway")
	}
	old, e := vpn.Open(p.Key, revision.VPN)
	if e != nil {
		t.Fatal(e)
	}
	next, e := vpn.Open(p.Key, steady.VPN)
	if e != nil {
		t.Fatal(e)
	}
	if next.Profile == nil || next.Profile.Version != 2 || !next.Profile.LoopbackOnly || next.Password != old.Password || next.CertificateVersion != old.CertificateVersion {
		t.Fatal("private plan lost version or rotated credential")
	}
}

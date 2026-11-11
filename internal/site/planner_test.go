package site

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

func plannerFixture(t *testing.T) (*Planner, settings.Site, control.Revision, *time.Time, []byte, []byte) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"probe.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	m := &certificates.Manager{PublishedDirectory: filepath.Join(t.TempDir(), "published"), ManagedDirectory: filepath.Join(t.TempDir(), "cache"), Roots: roots, Now: func() time.Time { return now }}
	prepared, err := m.Import("probe.test", chain, private)
	if err != nil {
		t.Fatal(err)
	}
	c := config.Config{Version: 1, Domain: "probe.test", AdminPort: 8007, ControlPort: 18090, VPNPort: 18443, DataDir: "data", VPNManagement: true, VPNAddresses: []string{"198.51.100.10"}}
	d := settings.FromLegacy(c)
	d.Site.ImportedVersion = prepared.Version
	base, err := vpn.SettingsFromConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	v := &settings.View{Deployment: c, Standard: true}
	p := &Planner{View: v, Certificates: m, VPNBase: base, Key: make([]byte, 32)}
	v.Ingress = p.Ingress
	desired := vpn.Desired{Enabled: true, Password: strings.Repeat("x", 43), CertificateVersion: prepared.Version}
	sealed, err := vpn.Seal(p.Key, desired)
	if err != nil {
		t.Fatal(err)
	}
	return p, d.Site, control.Revision{Number: 1, VPN: sealed, Rules: "[]"}, &now, chain, private
}

func TestPlannerDualPreservesVPNAndSteadyUsesCandidateProfile(t *testing.T) {
	p, current, revision, _, _, _ := plannerFixture(t)
	ctx := context.Background()
	candidate := current
	candidate.AdminPort = 8006
	candidate.VPNPort = 19443
	candidate.VPNAddresses = []string{"203.0.113.2"}
	dual, err := p.Dual(ctx, current, candidate, revision)
	if err != nil {
		t.Fatal(err)
	}
	if dual.VPN != revision.VPN || !strings.Contains(dual.Gateway, `":8007"`) || !strings.Contains(dual.Gateway, `":8006"`) {
		t.Fatal("dual entry changed VPN or lost listener", dual, err)
	}
	steady, err := p.Steady(ctx, candidate, revision)
	if err != nil {
		t.Fatal(err)
	}
	d, err := vpn.Open(p.Key, steady.VPN)
	if err != nil || d.Profile == nil || d.Profile.Port != 19443 || d.Password != strings.Repeat("x", 43) {
		t.Fatal("steady plan lost password or candidate runtime profile", err)
	}
	effective, err := vpn.EffectiveSettings(p.VPNBase, d)
	if err != nil || effective.Port != 19443 {
		t.Fatal(err)
	}
	protected := false
	for _, address := range effective.OwnAddresses {
		protected = protected || address == netip.MustParseAddr("198.51.100.10")
	}
	if !protected {
		t.Fatal("site plan removed deployment protected address")
	}
	if !strings.Contains(steady.Gateway, `":8006"`) || strings.Contains(steady.Gateway, `":8007"`) {
		t.Fatal("steady plan retained old admin listener")
	}
	withoutDomain := current
	withoutDomain.Domain = ""
	withoutDomain.CertificateSource = "none"
	withoutDomain.ImportedVersion = ""
	if _, err = p.Dual(ctx, current, withoutDomain, revision); err == nil {
		t.Fatal("domain removal allowed while VPN remained enabled")
	}
	bad := revision
	bad.VPN = "corrupt-ciphertext"
	if _, err = p.Dual(ctx, current, candidate, bad); err == nil {
		t.Fatal("corrupt VPN ciphertext silently replaced")
	}
	revision.VPN = ""
	if plan, err := p.Steady(ctx, withoutDomain, revision); err != nil || plan.VPN != "" || !strings.Contains(plan.Gateway, `"drop":true`) {
		t.Fatal("HTTP-only stopped VPN plan unavailable", err)
	}
}

func TestPlannerCertificateReadinessAndExpiryDriveIngress(t *testing.T) {
	p, current, _, now, chain, key := plannerFixture(t)
	ctx := context.Background()
	automatic := current
	automatic.CertificateSource = "automatic"
	automatic.ImportedVersion = ""
	i, err := p.Ingress(ctx, automatic)
	if err != nil || !i.AwaitCertificate {
		t.Fatal("missing automatic certificate falsely ready", i, err)
	}
	if err = p.Ready(ctx, automatic); err == nil {
		t.Fatal("candidate confirmed before certificate ready")
	}
	cache := filepath.Join(p.Certificates.ManagedDirectory, "fixture-issuer", "probe.test")
	if err = os.MkdirAll(cache, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(cache, "probe.test.crt"), chain, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(cache, "probe.test.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	i, err = p.Ingress(ctx, automatic)
	if err != nil || i.AwaitCertificate || p.Ready(ctx, automatic) != nil {
		t.Fatal("trusted automatic cache did not become ready", i, err)
	}
	*now = now.Add(2 * time.Hour)
	i, err = p.Ingress(ctx, current)
	if err != nil || i.Mode != "unavailable" {
		t.Fatal("expired imported certificate silently changed issuer", i, err)
	}
	s, err := p.View.ForSite(ctx, current)
	if err != nil {
		t.Fatal(err)
	}
	body, err := gateway.Compile(s, nil)
	if err != nil || !strings.Contains(body, `"drop":true`) || strings.Contains(body, `"status_code":308`) {
		t.Fatal("expired imported certificate did not preserve HTTP reservation", err)
	}
}

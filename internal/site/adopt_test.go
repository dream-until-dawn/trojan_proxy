package site

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

type adoptComponent struct {
	t       *testing.T
	key     []byte
	gateway bool
}

func (c adoptComponent) Check(_ context.Context, body string) error {
	if c.gateway {
		c.t.Fatal("legacy adoption changed gateway")
	}
	_, err := vpn.Open(c.key, body)
	return err
}
func (c adoptComponent) Apply(ctx context.Context, body string) error { return c.Check(ctx, body) }

func TestAdoptionIsOnceAndPreservesAccountRulesAndPassword(t *testing.T) {
	p, current, revision, _, chain, key := plannerFixture(t)
	ctx := context.Background()
	current.ImportedVersion = ""
	p.Certificates.LegacyDomain = current.Domain
	p.Certificates.LegacyDirectory = t.TempDir()
	if err := os.WriteFile(filepath.Join(p.Certificates.LegacyDirectory, "fullchain.cer"), chain, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Certificates.LegacyDirectory, "private.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	doc := settings.Document{Version: 1, Site: current}
	body, err := doc.Encode(p.View.Deployment)
	if err != nil {
		t.Fatal(err)
	}
	revision.Settings = body
	revision.Gateway = "opaque-current-gateway"
	revision.GatewaySettings = "previous-fingerprint"
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), revision)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	account := storage.Account{PasswordHash: "unchanged", Secret: []byte("encrypted-totp"), LastCounter: 321, Recovery: []string{"unspent"}}
	if err = db.CreateAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	coordinator := control.NewCoordinator(db, adoptComponent{t: t, gateway: true}, adoptComponent{t: t, key: p.Key})
	if err = p.AdoptLegacy(ctx, db, coordinator); err != nil {
		t.Fatal(err)
	}
	j, err := db.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if j.Applied.Number != revision.Number+1 || j.Applied.Gateway != revision.Gateway || j.Applied.GatewaySettings != revision.GatewaySettings || j.Applied.Rules != revision.Rules {
		t.Fatal("legacy adoption changed unrelated revision fields", j.Applied.Number)
	}
	updated, err := settings.Decode(j.Applied.Settings, p.View.Deployment)
	if err != nil || updated.Site.ImportedVersion == "" {
		t.Fatal("legacy certificate remained mutable", err)
	}
	desired, err := vpn.Open(p.Key, j.Applied.VPN)
	if err != nil || desired.Profile == nil || desired.Password != "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" || desired.Profile.Port != current.VPNPort {
		t.Fatal("legacy runtime changed password or endpoint", err)
	}
	loaded, err := db.Account(ctx)
	if err != nil || loaded.LastCounter != 321 || loaded.PasswordHash != "unchanged" || len(loaded.Recovery) != 1 {
		t.Fatal("legacy adoption reset authentication state", err)
	}
	// 固化后旧文件被移走也不再读取，不反复生成修订。
	if err = os.Remove(filepath.Join(p.Certificates.LegacyDirectory, "private.key")); err != nil {
		t.Fatal(err)
	}
	if err = p.AdoptLegacy(ctx, db, coordinator); err != nil {
		t.Fatal(err)
	}
	after, err := db.Load(ctx)
	if err != nil || after.Applied != j.Applied {
		t.Fatal("legacy adoption repeated or depended on old files", err)
	}
}

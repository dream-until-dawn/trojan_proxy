package settings

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

type untouchedEngine struct{ t *testing.T }

func (e untouchedEngine) Check(context.Context, string) error {
	e.t.Error("settings-only migration changed an engine")
	return nil
}
func (e untouchedEngine) Apply(context.Context, string) error {
	e.t.Error("settings-only migration changed an engine")
	return nil
}
func deployment() config.Config {
	return config.Config{Version: 1, Domain: "example.com", AdminPort: 8007, ControlPort: 18090, VPNPort: 18443, DataDir: "data", PublicDirectories: map[string]string{"downloads": "/srv/public/downloads"}, VPNManagement: true, VPNAddresses: []string{"198.51.100.10"}}
}

func TestImportOncePreservesFullRevisionAndAccount(t *testing.T) {
	ctx := context.Background()
	legacy := deployment()
	initial := control.Revision{Number: 7, Gateway: "old-gateway", VPN: "opaque-encrypted-vpn", Rules: "[]", GatewaySettings: "old-fingerprint"}
	path := filepath.Join(t.TempDir(), "control.db")
	db, err := storage.OpenJournal(ctx, path, initial)
	if err != nil {
		t.Fatal(err)
	}
	account := storage.Account{PasswordHash: "old-hash", Secret: []byte("encrypted-totp"), LastCounter: 321, Recovery: []string{"unspent-code"}}
	if err = db.CreateAccount(ctx, account); err != nil {
		t.Fatal(err)
	}
	coordinator := control.NewCoordinator(db, untouchedEngine{t}, untouchedEngine{t})
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := EnsureImported(ctx, db, coordinator, legacy); err != nil && !errors.Is(err, ErrPending) && !errors.Is(err, control.ErrRevisionConflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err = EnsureImported(ctx, db, coordinator, legacy); err != nil {
		t.Fatal("migration did not converge after contention", err)
	}
	journal, err := db.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := initial
	want.Number++
	want.Settings = journal.Applied.Settings
	if journal.Pending != nil || journal.Applied != want || want.Settings == "" {
		t.Fatal("migration changed other revision fields", journal)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.OpenJournal(ctx, path, control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	legacy.Domain = "changed-static.example"
	legacy.AdminPort = 8008
	coordinator = control.NewCoordinator(db, untouchedEngine{t}, untouchedEngine{t})
	document, err := EnsureImported(ctx, db, coordinator, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if document.Site.Domain != "example.com" || document.Site.AdminPort != 8007 {
		t.Fatal("static JSON overwrote persisted business settings")
	}
	after, err := db.Load(ctx)
	if err != nil || after.Applied != want {
		t.Fatal("restart repeated migration", after, err)
	}
	actual, err := db.Account(ctx)
	if err != nil || !reflect.DeepEqual(actual, account) {
		t.Fatal("migration changed authentication counters or recovery", err)
	}
}

func TestStrictSettingsAndTrustedMountBoundary(t *testing.T) {
	legacy := deployment()
	base := FromLegacy(legacy)
	if _, err := base.Encode(legacy); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"unknown-version", "reserved-port", "untrusted-root", "traversal", "absolute", "drive-path", "bad-domain", "bad-email", "no-certificate"} {
		t.Run(scenario, func(t *testing.T) {
			body, _ := json.Marshal(base)
			var candidate Document
			json.Unmarshal(body, &candidate)
			switch scenario {
			case "unknown-version":
				candidate.Version = 999
			case "reserved-port":
				candidate.Site.AdminPort = 18092
			case "untrusted-root":
				candidate.Site.Directories[0].Root = "secrets"
			case "traversal":
				candidate.Site.Directories[0].Relative = "../secret"
			case "absolute":
				candidate.Site.Directories[0].Relative = "/etc"
			case "drive-path":
				candidate.Site.Directories[0].Relative = "C:/Windows"
			case "bad-domain":
				candidate.Site.Domain = "https://example.com"
			case "bad-email":
				candidate.Site.ACMEEmail = "Someone <a@example.com>"
			case "no-certificate":
				candidate.Site.CertificateSource = "none"
			}
			if _, err := candidate.Encode(legacy); err == nil {
				t.Fatal("unsafe settings accepted", scenario)
			}
		})
	}
	for _, body := range []string{`{"version":1,"typo":true}`, `{} {}`, `{"version":999}`} {
		if _, err := Decode(body, legacy); err == nil {
			t.Fatal("malformed settings accepted")
		}
	}
}

func TestCorruptPersistedSettingsDoNotFallBackToLegacy(t *testing.T) {
	ctx := context.Background()
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), control.Revision{Number: 1, Settings: `{"version":999}`})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	coordinator := control.NewCoordinator(db, untouchedEngine{t}, untouchedEngine{t})
	if _, err = EnsureImported(ctx, db, coordinator, deployment()); err == nil {
		t.Fatal("corrupt stored settings silently replaced by legacy")
	}
	journal, err := db.Load(ctx)
	if err != nil || journal.Applied.Settings != `{"version":999}` || journal.Applied.Number != 1 {
		t.Fatal("failed migration changed corrupt snapshot", err)
	}
}

func TestPersistedSettingsSurviveStaticChanges(t *testing.T) {
	ctx := context.Background()
	legacy := deployment()
	document := FromLegacy(legacy)
	body, err := document.Encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), control.Revision{Number: 1, Settings: body})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	legacy.Domain = "modified-static.example"
	coordinator := control.NewCoordinator(db, untouchedEngine{t}, untouchedEngine{t})
	actual, err := EnsureImported(ctx, db, coordinator, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Site.Domain != "example.com" {
		t.Fatal("static JSON overwrote persisted business settings")
	}
}

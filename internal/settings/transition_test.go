package settings

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

type entryEngine struct{ value, fail string }

func (e *entryEngine) Check(context.Context, string) error { return nil }
func (e *entryEngine) Apply(_ context.Context, value string) error {
	if value == e.fail {
		return errors.New("fixture apply failure")
	}
	e.value = value
	return nil
}

type entryPlanner struct{ ready bool }

func TestTransitionRejectsVPNReuseOfRollbackAdminPort(t *testing.T) {
	m, store, engine, _, _ := transitionFixture(t)
	ctx := context.Background()
	j, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	document, err := Decode(j.Applied.Settings, m.deployment)
	if err != nil {
		t.Fatal(err)
	}
	candidate := document.Site
	candidate.AdminPort--
	candidate.VPNPort = document.Site.AdminPort
	if err = m.Propose(ctx, j.Applied.Number, candidate); err == nil {
		t.Fatal("transition allowed VPN to occupy rollback admin port")
	}
	after, err := store.Load(ctx)
	if err != nil || after.Applied.Number != j.Applied.Number || engine.value != "old-entry" {
		t.Fatal("rejected port exchange changed active revision", after.Applied.Number, err)
	}
}

func (p *entryPlanner) Dual(_ context.Context, _, _ Site, revision control.Revision) (Plan, error) {
	return Plan{Gateway: "dual-entry", VPN: revision.VPN, Fingerprint: "dual-fingerprint"}, nil
}
func (p *entryPlanner) Steady(_ context.Context, _ Site, revision control.Revision) (Plan, error) {
	return Plan{Gateway: "new-entry", VPN: revision.VPN, Fingerprint: "new-fingerprint"}, nil
}
func (p *entryPlanner) Ready(context.Context, Site) error {
	if !p.ready {
		return errors.New("fixture certificate pending")
	}
	return nil
}

func transitionFixture(t *testing.T) (*Manager, *storage.JournalStore, *entryEngine, *entryPlanner, *time.Time) {
	t.Helper()
	legacy := deployment()
	document := FromLegacy(legacy)
	body, err := document.Encode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.OpenJournal(context.Background(), filepath.Join(t.TempDir(), "control.db"), control.Revision{Number: 1, Gateway: "old-entry", VPN: "encrypted-existing-vpn", GatewaySettings: "old-fingerprint", Rules: "[]", Settings: body})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	engine := &entryEngine{value: "old-entry"}
	vpn := &entryEngine{value: "encrypted-existing-vpn"}
	planner := &entryPlanner{ready: true}
	manager := NewManager(db, control.NewCoordinator(db, engine, vpn), planner, legacy)
	now := time.Unix(1800000000, 0)
	manager.now = func() time.Time { return now }
	return manager, db, engine, planner, &now
}

func TestTransitionRequiresNewOriginAndReadyCertificate(t *testing.T) {
	m, db, engine, planner, _ := transitionFixture(t)
	ctx := context.Background()
	snapshot, err := m.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidate := snapshot.Site
	candidate.AdminPort = 8006
	if err = m.Propose(ctx, 1, candidate); err != nil {
		t.Fatal(err)
	}
	if engine.value != "dual-entry" {
		t.Fatal("old and new entries were not kept together")
	}
	if err = RequireStable(ctx, db, m.deployment); !errors.Is(err, ErrFrozen) {
		t.Fatal("ordinary writes allowed while entry waits for confirmation", err)
	}
	snapshot, err = m.Status(ctx)
	if err != nil || snapshot.Site.AdminPort != 8007 || snapshot.Candidate == nil || snapshot.Candidate.AdminPort != 8006 {
		t.Fatal("pending settings were reported as committed", snapshot, err)
	}
	public, _ := json.Marshal(snapshot)
	if strings.Contains(string(public), "encrypted-existing") || strings.Contains(string(public), "old-entry") {
		t.Fatal("entry status exposed recovery internals")
	}
	if err = m.Confirm(ctx, 2, "https://example.com:8007"); !errors.Is(err, ErrConfirmation) {
		t.Fatal("old entry confirmed the new endpoint", err)
	}
	planner.ready = false
	if err = m.Confirm(ctx, 2, "https://example.com:8006"); !errors.Is(err, ErrConfirmation) {
		t.Fatal("unready certificate accepted", err)
	}
	planner.ready = true
	if err = m.Confirm(ctx, 2, "https://example.com:8006"); err != nil {
		t.Fatal(err)
	}
	snapshot, err = m.Status(ctx)
	if err != nil || snapshot.Candidate != nil || snapshot.Site.AdminPort != 8006 || engine.value != "new-entry" {
		t.Fatal("confirmed entry not committed", snapshot, engine.value, err)
	}
	if err = RequireStable(ctx, db, m.deployment); err != nil {
		t.Fatal("writes remained frozen after confirmation", err)
	}
	if err = m.Confirm(ctx, 3, "https://example.com:8006"); !errors.Is(err, ErrConfirmation) {
		t.Fatal("confirmation replay accepted", err)
	}
}

func TestTransitionDeadlineSurvivesManagerRestart(t *testing.T) {
	m, db, engine, planner, now := transitionFixture(t)
	ctx := context.Background()
	snapshot, _ := m.Status(ctx)
	candidate := snapshot.Site
	candidate.AdminPort = 8006
	if err := m.Propose(ctx, 1, candidate); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Minute)
	restarted := NewManager(db, m.coordinator, planner, m.deployment)
	restarted.now = m.now
	if err := restarted.Confirm(ctx, 2, "https://example.com:8006"); !errors.Is(err, ErrConfirmation) {
		t.Fatal("expired confirmation accepted at deadline", err)
	}
	if err := restarted.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot, err := restarted.Status(ctx)
	if err != nil || snapshot.Candidate != nil || snapshot.Site.AdminPort != 8007 || engine.value != "old-entry" {
		t.Fatal("entry deadline did not restore old endpoint", snapshot, engine.value, err)
	}
	j, err := db.Load(ctx)
	if err != nil || j.Applied.VPN != "encrypted-existing-vpn" || j.Applied.GatewaySettings != "old-fingerprint" {
		t.Fatal("timeout changed VPN or lost old fingerprint", err)
	}
}

func TestFailedConfirmationKeepsRollbackAndCanCancel(t *testing.T) {
	m, _, engine, _, _ := transitionFixture(t)
	ctx := context.Background()
	snapshot, _ := m.Status(ctx)
	candidate := snapshot.Site
	candidate.AdminPort = 8006
	if err := m.Propose(ctx, 1, candidate); err != nil {
		t.Fatal(err)
	}
	engine.fail = "new-entry"
	if err := m.Confirm(ctx, 2, "https://example.com:8006"); err == nil {
		t.Fatal("failed gateway apply reported confirmation success")
	}
	snapshot, err := m.Status(ctx)
	if err != nil || snapshot.Candidate == nil || engine.value != "dual-entry" {
		t.Fatal("failed confirmation lost temporary state", snapshot, err)
	}
	if err = m.Cancel(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if engine.value != "old-entry" {
		t.Fatal("cancel did not restore old endpoint")
	}
}

func TestEntryCancellationPreservesBackgroundVPNRenewal(t *testing.T) {
	m, db, _, _, _ := transitionFixture(t)
	ctx := context.Background()
	snapshot, _ := m.Status(ctx)
	candidate := snapshot.Site
	candidate.AdminPort = 8006
	if err := m.Propose(ctx, 1, candidate); err != nil {
		t.Fatal(err)
	}
	j, err := db.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next := j.Applied
	next.Number++
	next.VPN = "renewed-old-identity-vpn"
	if err = m.coordinator.Apply(ctx, 2, next); err != nil {
		t.Fatal(err)
	}
	if err = m.Cancel(ctx, 3); err != nil {
		t.Fatal(err)
	}
	j, err = db.Load(ctx)
	if err != nil || j.Applied.VPN != "renewed-old-identity-vpn" {
		t.Fatal("entry cancellation reverted a valid background VPN renewal", err)
	}
}

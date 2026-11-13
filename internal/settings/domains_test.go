package settings

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func TestDomainValidationAndAdminOriginExpiry(t *testing.T) {
	c := deployment()
	c.StandardIngress = true
	d := FromLegacy(c)
	d.Site.Domains = []string{"proxy.example.com", "one.example.com"}
	d.Site.AdminDomain = "proxy.example.com"
	if e := d.Validate(c); e != nil {
		t.Fatal(e)
	}
	if got := AdminEndpoint(d.Site, c.ControlPort).Identity(); got != "https://proxy.example.com" {
		t.Fatal("admin hostname incorrectly changed VPN identity", got)
	}
	for _, names := range [][]string{{"bad.test"}, {"*.example.com"}, {"ONE.example.com"}, {"one.example.com", "one.example.com"}, {"example.com"}} {
		bad := d
		bad.Site.Domains = names
		if bad.Validate(c) == nil {
			t.Fatal("invalid domain accepted", names)
		}
	}
	current := FromLegacy(c)
	current.Site.AdminPath = "/proxy"
	now := time.Unix(1800000000, 0)
	current.Pending = &Transition{Candidate: d.Site, Deadline: now.Add(time.Minute).Unix()}
	body, e := current.Encode(c)
	if e != nil {
		t.Fatal(e)
	}
	db, e := storage.OpenJournal(context.Background(), filepath.Join(t.TempDir(), "control.db"), control.Revision{Number: 1, Settings: body})
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	view := &View{Store: db, Deployment: c, Now: func() time.Time { return now }}
	origins, e := view.Origins(context.Background())
	if e != nil || !origins["https://example.com"] || !origins["https://proxy.example.com"] || origins["https://one.example.com"] {
		t.Fatal("business domain became admin origin", origins, e)
	}
	now = time.Unix(current.Pending.Deadline, 0)
	origins, e = view.Origins(context.Background())
	if e != nil || origins["https://proxy.example.com"] {
		t.Fatal("expired admin hostname remained trusted", origins, e)
	}
}

func TestAdminDomainConfirmationUsesNewOriginAndExpires(t *testing.T) {
	m, store, _, planner, now := transitionFixture(t)
	m.deployment.StandardIngress = true
	ctx := context.Background()
	snapshot, _ := m.Status(ctx)
	candidate := snapshot.Site
	candidate.Domains = []string{"proxy.example.com", "one.example.com"}
	candidate.AdminDomain = "proxy.example.com"
	if e := m.Propose(ctx, 1, candidate); e != nil {
		t.Fatal(e)
	}
	for _, old := range []string{"https://example.com:8007", "https://example.com/proxy", "https://one.example.com"} {
		if e := m.Confirm(ctx, 2, old); !errors.Is(e, ErrConfirmation) {
			t.Fatal("old or business origin confirmed admin domain", old, e)
		}
	}
	planner.ready = false
	if e := m.Confirm(ctx, 2, "https://proxy.example.com"); !errors.Is(e, ErrConfirmation) {
		t.Fatal("unready administrator certificate confirmed")
	}
	planner.ready = true
	if e := m.Confirm(ctx, 2, "https://proxy.example.com"); e != nil {
		t.Fatal(e)
	}
	j, e := store.Load(ctx)
	if e != nil || j.Applied.VPN != "encrypted-existing-vpn" {
		t.Fatal("admin domain changed VPN", e)
	}
	snapshot, _ = m.Status(ctx)
	candidate = snapshot.Site
	candidate.AdminDomain = "one.example.com"
	if e := m.Propose(ctx, 3, candidate); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(5 * time.Minute)
	if e := m.Confirm(ctx, 4, "https://one.example.com"); !errors.Is(e, ErrConfirmation) {
		t.Fatal("expired administrator domain confirmed")
	}
	if e := m.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	snapshot, _ = m.Status(ctx)
	if snapshot.Site.AdminDomain != "proxy.example.com" || snapshot.Candidate != nil {
		t.Fatal("administrator domain did not revert after expiry", snapshot)
	}
}

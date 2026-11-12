package settings

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPathConfirmationUsesFullEndpointIdentity(t *testing.T) {
	m, _, engine, _, _ := transitionFixture(t)
	m.deployment.StandardIngress = true
	ctx := context.Background()
	snapshot, _ := m.Status(ctx)
	candidate := snapshot.Site
	candidate.AdminPath = "/proxy"
	if err := m.Propose(ctx, 1, candidate); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = m.Status(ctx)
	if snapshot.CandidateEntry != "https://example.com/proxy" || snapshot.CandidateOrigin != "https://example.com" {
		t.Fatal(snapshot)
	}
	for _, old := range []string{"https://example.com:8007", "https://example.com", "https://example.com/proxy-other"} {
		if err := m.Confirm(ctx, 2, old); !errors.Is(err, ErrConfirmation) {
			t.Fatal("wrong management identity confirmed candidate", old, err)
		}
	}
	if err := m.Confirm(ctx, 2, "https://example.com/proxy"); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = m.Status(ctx)
	if snapshot.Site.AdminPath != "/proxy" || snapshot.Candidate != nil || engine.value != "new-entry" {
		t.Fatal(snapshot, engine.value)
	}
	candidate = snapshot.Site
	candidate.AdminPath = "/admin"
	if err := m.Propose(ctx, 3, candidate); err != nil {
		t.Fatal(err)
	}
	if err := m.Confirm(ctx, 4, "https://example.com/proxy"); !errors.Is(err, ErrConfirmation) {
		t.Fatal("same-origin old path confirmed new path", err)
	}
	if err := m.Confirm(ctx, 4, "https://example.com/admin"); err != nil {
		t.Fatal(err)
	}
}

func TestPathCandidateExpiresAndRestoresLegacyEntry(t *testing.T) {
	m, store, engine, _, now := transitionFixture(t)
	m.deployment.StandardIngress = true
	ctx := context.Background()
	s, _ := m.Status(ctx)
	candidate := s.Site
	candidate.AdminPath = "/proxy"
	if err := m.Propose(ctx, 1, candidate); err != nil {
		t.Fatal(err)
	}
	view := &View{Store: store, Deployment: m.deployment, Now: m.now}
	entries, err := view.Endpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Prefix == "/proxy" {
			found = true
		}
	}
	if !found {
		t.Fatal("live candidate missing")
	}
	*now = now.Add(5 * time.Minute)
	entries, err = view.Endpoints(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Prefix == "/proxy" {
			t.Fatal("expired candidate still allowed")
		}
	}
	if err = m.Confirm(ctx, 2, "https://example.com/proxy"); !errors.Is(err, ErrConfirmation) {
		t.Fatal("expired path confirmed", err)
	}
	if err = m.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	s, err = m.Status(ctx)
	if err != nil || s.Site.AdminPath != "" || s.Candidate != nil || engine.value != "old-entry" {
		t.Fatal("legacy entry not restored", s, engine.value, err)
	}
}

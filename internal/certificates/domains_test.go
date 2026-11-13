package certificates

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdditionalCertificateFailureDoesNotHidePrimary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	chain, key, roots := fixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	m := &Manager{PublishedDirectory: filepath.Join(t.TempDir(), "published"), ManagedDirectory: filepath.Join(t.TempDir(), "cache"), Roots: roots, Now: func() time.Time { return now }}
	prepared, e := m.Import("probe.test", chain, key)
	if e != nil {
		t.Fatal(e)
	}
	m.Current = func(context.Context) (Selection, error) {
		return Selection{Domain: "probe.test", Source: "imported", ImportedVersion: prepared.Version}, nil
	}
	m.Additional = func(context.Context) ([]Selection, error) {
		return []Selection{{Domain: "pending.probe.test", Source: "automatic"}}, nil
	}
	state, e := m.Status(context.Background())
	if e != nil || !state.Ready || state.Info == nil || len(state.Domains) != 1 || state.Domains[0].Ready {
		t.Fatal("additional failure contaminated primary certificate state", state, e)
	}
	public, _ := json.Marshal(state)
	if strings.Contains(string(public), m.ManagedDirectory) || strings.Contains(string(public), "PRIVATE KEY") {
		t.Fatal("additional certificate state leaked materials")
	}
}

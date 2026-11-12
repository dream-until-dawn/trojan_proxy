package storage

import (
	"context"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"path/filepath"
	"testing"
)

func TestAdminPathFormatProtectsCandidatesAndCompatibleRollback(t *testing.T) {
	ctx := context.Background()
	initial := control.Revision{Number: 1, Rules: `[{"https":true}]`, Settings: `{"site":{}}`}
	store, err := OpenJournal(ctx, filepath.Join(t.TempDir(), "path.db"), initial)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	version := func() int {
		t.Helper()
		var v int
		if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	candidate := initial
	candidate.Number = 2
	candidate.Settings = `{"site":{},"pending":{"candidate":{"admin_path":"/proxy"}}}`
	if err = store.Save(ctx, control.Journal{Applied: initial, Pending: &candidate}); err != nil {
		t.Fatal(err)
	}
	if version() != 5 {
		t.Fatal("path candidate did not reject legacy readers")
	}
	if _, err = store.DowngradeCompatibleFormat(ctx, 4); err == nil {
		t.Fatal("prepared path downgraded")
	}
	if err = store.Save(ctx, control.Journal{Applied: candidate}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DowngradeCompatibleFormat(ctx, 4); err == nil {
		t.Fatal("active settings candidate downgraded")
	}
	candidate.Settings = `{"site":{"admin_path":"/proxy"}}`
	candidate.Number = 3
	previous, _ := store.Load(ctx)
	if err = store.Save(ctx, control.Journal{Applied: previous.Applied, Pending: &candidate}); err != nil {
		t.Fatal(err)
	}
	if err = store.Save(ctx, control.Journal{Applied: candidate}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DowngradeCompatibleFormat(ctx, 4); err == nil {
		t.Fatal("active path downgraded")
	}
	initial.Number = 4
	if err = store.Save(ctx, control.Journal{Applied: candidate, Pending: &initial}); err != nil {
		t.Fatal(err)
	}
	if err = store.Save(ctx, control.Journal{Applied: initial}); err != nil {
		t.Fatal(err)
	}
	if version() != 5 {
		t.Fatal("path rollback silently downgraded format")
	}
	if _, err = store.DowngradeCompatibleFormat(ctx, 3); err == nil {
		t.Fatal("HTTPS rules downgraded to format3")
	}
	if got, err := store.DowngradeCompatibleFormat(ctx, 4); err != nil || got != 4 || version() != 4 {
		t.Fatal("safe explicit rollback to HTTPS reader failed", got, err)
	}
}

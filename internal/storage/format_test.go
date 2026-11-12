package storage

import (
	"context"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"path/filepath"
	"testing"
)

func TestHTTPSFormatProtectsPreparedAndRolledBackRules(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "control.db")
	initial := control.Revision{Number: 1, Rules: "[]"}
	store, err := OpenJournal(ctx, path, initial)
	if err != nil {
		t.Fatal(err)
	}
	version := func() int {
		t.Helper()
		var v int
		if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if version() != 2 {
		t.Fatal("legacy HTTP format changed")
	}
	next := control.Revision{Number: 2, Rules: `[{"id":"secure","https":true}]`}
	if err = store.Save(ctx, control.Journal{Applied: initial, Pending: &next}); err != nil {
		t.Fatal(err)
	}
	if version() != 4 {
		t.Fatal("HTTPS preparation did not reject legacy readers")
	}
	if _, err = store.DowngradeHTTPFormat(ctx); err == nil {
		t.Fatal("pending HTTPS format downgrade accepted")
	}
	if err = store.Save(ctx, control.Journal{Applied: initial}); err != nil {
		t.Fatal(err)
	}
	if version() != 4 {
		t.Fatal("HTTPS rollback silently downgraded format")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenJournal(ctx, path, initial)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if version() != 4 {
		t.Fatal("HTTPS reopen silently downgraded format")
	}
	if result, err := store.DowngradeHTTPFormat(ctx); err != nil || result != 2 || version() != 2 {
		t.Fatal("safe offline format rollback failed", result, err)
	}
	if err = store.Save(ctx, control.Journal{Applied: initial, Pending: &next}); err != nil {
		t.Fatal(err)
	}
	if err = store.Save(ctx, control.Journal{Applied: next}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.DowngradeHTTPFormat(ctx); err == nil || version() != 4 {
		t.Fatal("active HTTPS format downgrade accepted")
	}
	if _, err = RequiredJournalVersion(control.Journal{Applied: control.Revision{Rules: `[{"https":"yes"}]`}}); err == nil {
		t.Fatal("malformed HTTPS flag accepted")
	}
}

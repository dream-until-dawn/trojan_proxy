package storage

import (
	"context"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"path/filepath"
	"testing"
)

func TestPrivateListenerFormatAndSafeRollback(t *testing.T) {
	ctx := context.Background()
	base := control.Revision{Number: 1, Settings: "{\"version\":1,\"site\":{\"shared_trojan_443\":true}}", Rules: "[]"}
	db, e := OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), base)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	next := base
	next.Number++
	next.Settings = "{\"version\":1,\"site\":{\"shared_trojan_443\":true,\"vpn_loopback_only\":true}}"
	back := base
	back.Number = next.Number + 1
	if v, e := RequiredJournalVersion(control.Journal{Applied: next, Pending: &back}); e != nil || v != 8 {
		t.Fatal("private format computation fell below 8", v, e)
	}
	if e = db.Save(ctx, control.Journal{Applied: base, Pending: &next}); e != nil {
		t.Fatal(e)
	}
	var v int
	db.db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != 8 {
		t.Fatal("prepared private mode not format protected", v)
	}
	if _, e = db.DowngradeCompatibleFormat(ctx, 7); e == nil {
		t.Fatal("prepared private format downgraded")
	}
	if e = db.Save(ctx, control.Journal{Applied: next}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.DowngradeCompatibleFormat(ctx, 7); e == nil {
		t.Fatal("active private format downgraded")
	}
	if e = db.Save(ctx, control.Journal{Applied: next, Pending: &back}); e != nil {
		t.Fatal(e)
	}
	if e = db.Save(ctx, control.Journal{Applied: back}); e != nil {
		t.Fatal(e)
	}
	if v, e = db.DowngradeCompatibleFormat(ctx, 7); e != nil || v != 7 {
		t.Fatal("safe private format rollback failed", v, e)
	}
}

package storage

import (
	"context"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"path/filepath"
	"testing"
)

func TestShared443FormatPreparationAndRollback(t *testing.T) {
	ctx := context.Background()
	base := control.Revision{Number: 1, Settings: "{\"version\":1,\"site\":{\"domains\":[\"proxy.example.test\"]}}", Rules: "[]"}
	db, e := OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), base)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	next := base
	next.Number++
	next.Settings = "{\"version\":1,\"site\":{\"domains\":[\"proxy.example.test\"],\"shared_trojan_443\":true}}"
	pending := base
	pending.Number = next.Number + 1
	if required, e := RequiredJournalVersion(control.Journal{Applied: next, Pending: &pending}); e != nil || required != 7 {
		t.Fatal("shared format computation fell below 7", required, e)
	}
	if e = db.Save(ctx, control.Journal{Applied: base, Pending: &next}); e != nil {
		t.Fatal(e)
	}
	if e = db.Save(ctx, control.Journal{Applied: next}); e != nil {
		t.Fatal(e)
	}
	if e = db.Save(ctx, control.Journal{Applied: next, Pending: &pending}); e != nil {
		t.Fatal(e)
	}
	var v int
	db.db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != 7 {
		t.Fatal("shared format not protected with older pending revision", v)
	}
	if _, e = db.DowngradeCompatibleFormat(ctx, 6); e == nil {
		t.Fatal("pending shared format downgraded")
	}
	if e = db.Save(ctx, control.Journal{Applied: next}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.DowngradeCompatibleFormat(ctx, 6); e == nil {
		t.Fatal("active shared format downgraded")
	}
	if e = db.Save(ctx, control.Journal{Applied: next, Pending: &pending}); e != nil {
		t.Fatal(e)
	}
	if e = db.Save(ctx, control.Journal{Applied: pending}); e != nil {
		t.Fatal(e)
	}
	db.db.QueryRow("PRAGMA user_version").Scan(&v)
	if v != 7 {
		t.Fatal("automatic shared format downgrade")
	}
	if v, e = db.DowngradeCompatibleFormat(ctx, 6); e != nil || v != 6 {
		t.Fatal("safe shared format rollback failed", v, e)
	}
	// 候选设置尚未确认也必须提前升级格式。
	base.Settings = "{\"version\":1,\"site\":{},\"pending\":{\"candidate\":{\"shared_trojan_443\":true}}}"
	if required, e := RequiredJournalVersion(control.Journal{Applied: base}); e != nil || required != 7 {
		t.Fatal("candidate shared format ignored", required, e)
	}
}

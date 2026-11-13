package storage

import (
	"context"
	"path/filepath"
	"testing"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

func TestDomainFormatPreparedRollbackAndSafeDowngrade(t *testing.T) {
	ctx := context.Background()
	base := control.Revision{Number: 1, Rules: "[]", Settings: `{"version":1,"site":{"admin_path":"/proxy"}}`}
	db, e := OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), base)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	next := base
	next.Number++
	next.Settings = `{"version":1,"site":{"admin_path":"/proxy"},"pending":{"candidate":{"domains":["proxy.example.test"],"admin_domain":"proxy.example.test"}}}`
	if e = db.Save(ctx, control.Journal{Applied: base, Pending: &next}); e != nil {
		t.Fatal(e)
	}
	var version int
	db.db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 6 {
		t.Fatal("prepared domains not format protected", version)
	}
	if _, e = db.DowngradeCompatibleFormat(ctx, 5); e == nil {
		t.Fatal("pending domains downgraded")
	}
	if e = db.Save(ctx, control.Journal{Applied: next}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.DowngradeCompatibleFormat(ctx, 5); e == nil {
		t.Fatal("active domains downgraded")
	}
	back := base
	back.Number = next.Number + 1
	if e = db.Save(ctx, control.Journal{Applied: next, Pending: &back}); e != nil {
		t.Fatal(e)
	}
	if e = db.Save(ctx, control.Journal{Applied: back}); e != nil {
		t.Fatal(e)
	}
	db.db.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 6 {
		t.Fatal("rollback silently downgraded domains format")
	}
	if got, e := db.DowngradeCompatibleFormat(ctx, 5); e != nil || got != 5 {
		t.Fatal("compatible format5 rollback failed", got, e)
	}
}

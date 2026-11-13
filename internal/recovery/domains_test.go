package recovery

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func TestDomainFormatBackupRestoreAndMislabelRejection(t *testing.T) {
	ctx := context.Background()
	c, store, _ := recoveryFixture(t)
	c.StandardIngress = true
	j, e := store.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	document, e := settings.Decode(j.Applied.Settings, c)
	if e != nil {
		t.Fatal(e)
	}
	document.Site.Domain = "qin-xin.top"
	document.Site.CertificateSource = "automatic"
	document.Site.Domains = []string{"proxy.qin-xin.top", "flow.qin-xin.top"}
	document.Site.AdminDomain = "proxy.qin-xin.top"
	next := j.Applied
	next.Number++
	next.Settings, e = document.Encode(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Save(ctx, control.Journal{Applied: j.Applied, Pending: &next}); e != nil {
		t.Fatal(e)
	}
	if e = store.Save(ctx, control.Journal{Applied: next}); e != nil {
		t.Fatal(e)
	}
	report, e := Backup(ctx, c, filepath.Join(t.TempDir(), "domains.tgz"))
	if e != nil {
		t.Fatal(e)
	}
	target := c
	target.DataDir = t.TempDir()
	if e = Restore(ctx, target, report.Path, report.SHA256); e != nil {
		t.Fatal(e)
	}
	reopened, e := storage.OpenJournal(ctx, filepath.Join(target.DataDir, "control.db"), control.Revision{Number: 1})
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	restored, e := reopened.Load(ctx)
	if e != nil || restored.Applied.Settings != next.Settings {
		t.Fatal("domain backup lost identity", e)
	}
	copied := filepath.Join(t.TempDir(), "mislabelled.db")
	if e = store.BackupInto(ctx, copied); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", copied)
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec("PRAGMA user_version=5")
	db.Close()
	if e != nil {
		t.Fatal(e)
	}
	key, e := os.ReadFile(filepath.Join(c.DataDir, "master.key"))
	if e != nil {
		t.Fatal(e)
	}
	if validateDatabase(ctx, copied, key, c) == nil {
		t.Fatal("domain backup accepted format5 label")
	}
}

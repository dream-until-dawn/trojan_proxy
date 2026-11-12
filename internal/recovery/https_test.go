package recovery

import (
	"context"
	"database/sql"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPSFormatBackupRestoreAndRejectMislabelledDatabase(t *testing.T) {
	c, store, _ := recoveryFixture(t)
	ctx := context.Background()
	j, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	document, err := settings.Decode(j.Applied.Settings, c)
	if err != nil {
		t.Fatal(err)
	}
	document.Site.Domain = "qin-xin.top"
	document.Site.CertificateSource = "automatic"
	next := j.Applied
	next.Number++
	next.Settings, err = document.Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	next.Rules = `[{"id":"secure","name":"HTTPS","port":8001,"host":"qin-xin.top","path":"/","kind":"proxy","upstream_ip":"127.0.0.1","upstream_port":3030,"https":true}]`
	if err = store.Save(ctx, control.Journal{Applied: j.Applied, Pending: &next}); err != nil {
		t.Fatal(err)
	}
	if err = store.Save(ctx, control.Journal{Applied: next}); err != nil {
		t.Fatal(err)
	}
	report, err := Backup(ctx, c, filepath.Join(t.TempDir(), "https.tgz"))
	if err != nil {
		t.Fatal("HTTPS backup failed", err)
	}
	target := c
	target.DataDir = t.TempDir()
	if err = Restore(ctx, target, report.Path, report.SHA256); err != nil {
		t.Fatal("HTTPS cold restore failed", err)
	}
	restored, err := storage.OpenJournal(ctx, filepath.Join(target.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	actual, err := restored.Load(ctx)
	restored.Close()
	if err != nil || actual.Applied.Rules != next.Rules {
		t.Fatal("HTTPS restore lost TLS semantics", err)
	}
	copyPath := filepath.Join(t.TempDir(), "mislabelled.db")
	if err = store.BackupInto(ctx, copyPath); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", copyPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, "PRAGMA user_version=3")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(filepath.Join(c.DataDir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	err = validateDatabase(ctx, copyPath, key, c)
	if err == nil || !strings.Contains(err.Error(), "备份格式版本不足以保护HTTPS规则") {
		t.Fatal("mislabelled HTTPS backup accepted", err)
	}
}

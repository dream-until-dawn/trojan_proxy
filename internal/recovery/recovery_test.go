package recovery

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/maintenance"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func recoveryFixture(t *testing.T) (config.Config, *storage.JournalStore, Report) {
	t.Helper()
	ctx := context.Background()
	c := config.Config{Version: 1, AdminPort: 8007, ControlPort: 18090, VPNPort: 18443, DataDir: t.TempDir(), StandardIngress: true}
	key, err := auth.LoadKey(filepath.Join(c.DataDir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := auth.EncryptSecret(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	body, err := settings.FromLegacy(c).Encode(c)
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.OpenJournal(ctx, filepath.Join(c.DataDir, "control.db"), control.Revision{Number: 7, Gateway: `{"apps":{}}`, Rules: "[]", Settings: body})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	codes := []string{}
	for i := 0; i < 8; i++ {
		codes = append(codes, auth.TokenHash("fixture-code-"+string(rune('a'+i))))
	}
	if err = db.CreateAccount(ctx, storage.Account{PasswordHash: "fixture-hash", Secret: encrypted, LastCounter: 321, Recovery: codes}); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.DataDir, "traffic.db"), []byte("traffic-private-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	shared, err := maintenance.Acquire(c.DataDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	report, err := Backup(ctx, c, filepath.Join(t.TempDir(), "backup.tgz"))
	if err != nil {
		t.Fatal(err)
	}
	return c, db, report
}

func archiveEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	zipper, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer zipper.Close()
	reader := tar.NewReader(zipper)
	entries := map[string][]byte{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		entries[header.Name] = body
	}
	return entries
}

func writeArchive(t *testing.T, entries map[string][]byte) (string, string) {
	t.Helper()
	var compressed bytes.Buffer
	zipper := gzip.NewWriter(&compressed)
	writer := tar.NewWriter(zipper)
	for name, body := range entries {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zipper.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.tgz")
	if err := os.WriteFile(path, compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(compressed.Bytes())
	return path, hex.EncodeToString(digest[:])
}

func TestOnlineBackupAndColdRestorePreserveStateAndRequireRebinding(t *testing.T) {
	c, source, report := recoveryFixture(t)
	ctx := context.Background()
	entries := archiveEntries(t, report.Path)
	if len(entries) != 4 || len(entries["master.key"]) != 32 || entries["traffic.db"] != nil || bytes.Contains(entries["control.db"], []byte("traffic-private-sentinel")) {
		t.Fatal("backup included statistics or omitted required state")
	}
	target := c
	target.DataDir = t.TempDir()
	if err := Restore(ctx, target, report.Path, report.SHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target.DataDir, "recovery-required")); err != nil {
		t.Fatal("cold restore did not require authentication rebinding", err)
	}
	restored, err := storage.OpenJournal(ctx, filepath.Join(target.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	want, err := source.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restored.Load(ctx)
	if err != nil || got.Applied != want.Applied {
		t.Fatal("cold restore changed business revision", err)
	}
	account, err := restored.Account(ctx)
	if err != nil || account.LastCounter != 321 || len(account.Recovery) != 8 {
		t.Fatal("cold restore omitted authentication state", err)
	}
	if err = Restore(ctx, target, report.Path, report.SHA256); err == nil {
		t.Fatal("cold restore overwrote populated data volume")
	}
}

func TestRestoreRejectsBadDigestArchiveAndLiveControl(t *testing.T) {
	c, _, report := recoveryFixture(t)
	ctx := context.Background()
	for _, kind := range []string{"digest", "traversal", "extra-file", "missing-key", "manifest-version", "database"} {
		t.Run(kind, func(t *testing.T) {
			entries := archiveEntries(t, report.Path)
			path, digest := report.Path, report.SHA256
			switch kind {
			case "digest":
				digest = strings.Repeat("0", 64)
			case "traversal":
				entries["../outside"] = []byte("sentinel")
			case "extra-file":
				entries["traffic.db"] = []byte("must-not-restore")
			case "missing-key":
				delete(entries, "master.key")
			case "manifest-version":
				var m manifest
				json.Unmarshal(entries["manifest.json"], &m)
				m.Version = 999
				entries["manifest.json"], _ = json.Marshal(m)
			case "database":
				entries["control.db"] = []byte("not-a-database")
				var m manifest
				json.Unmarshal(entries["manifest.json"], &m)
				h := sha256.Sum256(entries["control.db"])
				m.Files["control.db"] = hex.EncodeToString(h[:])
				entries["manifest.json"], _ = json.Marshal(m)
			}
			if kind != "digest" {
				path, digest = writeArchive(t, entries)
			}
			target := c
			target.DataDir = t.TempDir()
			if err := Restore(ctx, target, path, digest); err == nil {
				t.Fatal("unsafe backup accepted", kind)
			}
			if _, err := os.Stat(filepath.Join(target.DataDir, "control.db")); !os.IsNotExist(err) {
				t.Fatal("rejected backup changed active data", kind, err)
			}
		})
	}
	target := c
	target.DataDir = t.TempDir()
	live, err := maintenance.Acquire(target.DataDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err = Restore(ctx, target, report.Path, report.SHA256); err != maintenance.ErrInUse {
		t.Fatal("restore bypassed live control lock", err)
	}
}

func TestRestoreIntegrityCheckIsIndependentOfReadableAccountTables(t *testing.T) {
	c, _, report := recoveryFixture(t)
	entries := archiveEntries(t, report.Path)
	path := filepath.Join(t.TempDir(), "corrupt.db")
	if err := os.WriteFile(path, entries["control.db"], 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE corruption_sentinel(value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO corruption_sentinel VALUES('unused table only')"); err != nil {
		t.Fatal(err)
	}
	var page, pageSize int
	if err = db.QueryRow("SELECT rootpage FROM sqlite_master WHERE name='corruption_sentinel'").Scan(&page); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	db.Close()
	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], 65535)
	if _, err = file.WriteAt(count[:], int64((page-1)*pageSize+3)); err != nil {
		t.Fatal(err)
	}
	file.Close()
	entries["control.db"], err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	json.Unmarshal(entries["manifest.json"], &m)
	digest := sha256.Sum256(entries["control.db"])
	m.Files["control.db"] = hex.EncodeToString(digest[:])
	entries["manifest.json"], _ = json.Marshal(m)
	archive, sha := writeArchive(t, entries)
	target := c
	target.DataDir = t.TempDir()
	err = Restore(context.Background(), target, archive, sha)
	if err == nil || !strings.Contains(err.Error(), "完整性检查失败") {
		t.Fatal("independent SQLite integrity check did not reject unused corrupted table", err)
	}
}

func TestRestoreQuotaAndUnrelatedNonemptyDirectory(t *testing.T) {
	c, _, report := recoveryFixture(t)
	ctx := context.Background()
	entries := archiveEntries(t, report.Path)
	entries["deployment.json"] = append(entries["deployment.json"], bytes.Repeat([]byte(" "), (1<<20)+1-len(entries["deployment.json"]))...)
	var m manifest
	json.Unmarshal(entries["manifest.json"], &m)
	digest := sha256.Sum256(entries["deployment.json"])
	m.Files["deployment.json"] = hex.EncodeToString(digest[:])
	entries["manifest.json"], _ = json.Marshal(m)
	archive, sha := writeArchive(t, entries)
	target := c
	target.DataDir = t.TempDir()
	if err := Restore(ctx, target, archive, sha); err == nil || !strings.Contains(err.Error(), "超限条目") {
		t.Fatal("oversized valid JSON bypassed archive quota", err)
	}
	target.DataDir = t.TempDir()
	sentinel := filepath.Join(target.DataDir, "foreign.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, target, report.Path, report.SHA256); err == nil {
		t.Fatal("cold restore touched nonempty user directory")
	}
	if body, err := os.ReadFile(sentinel); err != nil || string(body) != "keep" {
		t.Fatal("cold restore changed unrelated file", err)
	}
}

func TestRestoreRetainsDeploymentProtectionBaseline(t *testing.T) {
	c, _, report := recoveryFixture(t)
	for _, change := range []func(*config.Config){
		func(c *config.Config) { c.Domain = "example.com" },
		func(c *config.Config) { c.StandardIngress = false },
		func(c *config.Config) { c.VPNAddresses = []string{"203.0.113.1"} },
		func(c *config.Config) { c.AdminPort = 8006 },
	} {
		target := c
		target.DataDir = t.TempDir()
		change(&target)
		err := Restore(context.Background(), target, report.Path, report.SHA256)
		if err == nil || !strings.Contains(err.Error(), "沿用备份的部署参数") {
			t.Fatal("restore silently replaced deployment protection baseline", err)
		}
		if _, err := os.Stat(filepath.Join(target.DataDir, "control.db")); !os.IsNotExist(err) {
			t.Fatal("incompatible restore installed database", err)
		}
	}
}

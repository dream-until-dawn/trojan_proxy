//go:build integration && linux

package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

// diskFullEngine 仅替代外部引擎；持久化、文件系统和写满错误均使用真实实现。
type diskFullEngine struct {
	value   string
	applied []string
	onApply func(string)
}

func (e *diskFullEngine) Check(context.Context, string) error { return nil }
func (e *diskFullEngine) Apply(_ context.Context, value string) error {
	e.value = value
	e.applied = append(e.applied, value)
	if e.onApply != nil {
		e.onApply(value)
	}
	return nil
}

func fillIsolatedDisk(t *testing.T, directory string) string {
	t.Helper()
	path := filepath.Join(directory, "fill.bin")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	chunk := make([]byte, 64*1024)
	for written := 0; written <= 16*1024*1024; {
		n, writeErr := f.Write(chunk)
		written += n
		if writeErr != nil {
			if !errors.Is(writeErr, syscall.ENOSPC) {
				t.Fatal("fixture did not reach real ENOSPC", writeErr)
			}
			t.Logf("real ENOSPC after %d filler bytes", written)
			return path
		}
	}
	t.Fatal("bounded tmpfs did not fill within budget")
	return ""
}

func TestRealJournalDiskFullRecovery(t *testing.T) {
	if os.Getenv("TROJAN_DISK_FULL_TEST") != "1" {
		t.Skip("requires disposable bounded tmpfs fixture")
	}
	const mount = "/probe-data"
	var fs syscall.Statfs_t
	if err := syscall.Statfs(mount, &fs); err != nil {
		t.Fatal(err)
	}
	if fs.Type != 0x01021994 || fs.Blocks*uint64(fs.Bsize) > 16*1024*1024 || fs.Blocks*uint64(fs.Bsize) < 4*1024*1024 {
		t.Fatal("disk-full fixture must be tmpfs between 4 and 16 MiB")
	}
	for _, stage := range []string{"prepare", "commit"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			directory, err := os.MkdirTemp(mount, stage+"-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(directory)
			path := filepath.Join(directory, "control.db")
			old := control.Revision{Number: 1, Gateway: "old-g", VPN: "old-v", Rules: "[]"}
			db, err := OpenJournal(ctx, path, old)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { db.Close() }()
			account := Account{PasswordHash: "synthetic-fixture-hash", Secret: []byte("synthetic-encrypted-secret"), LastCounter: 41, Recovery: []string{"unused", "consumed"}}
			if err = db.CreateAccount(ctx, account); err != nil {
				t.Fatal(err)
			}
			if ok, err := db.ConsumeRecovery(ctx, "consumed"); err != nil || !ok {
				t.Fatal("fixture recovery consumption", ok, err)
			}
			account, err = db.Account(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
				t.Fatal(err)
			}
			g, v := &diskFullEngine{value: old.Gateway}, &diskFullEngine{value: old.VPN}
			next := control.Revision{Number: 2, Gateway: "new-g", VPN: "new-v", Rules: "[]", Settings: strings.Repeat("fixture-opaque-settings-", 50000)}
			filler := ""
			if stage == "prepare" {
				filler = fillIsolatedDisk(t, directory)
			} else {
				v.onApply = func(value string) {
					if value == next.VPN && filler == "" {
						filler = fillIsolatedDisk(t, directory)
					}
				}
			}
			err = control.NewCoordinator(db, g, v).Apply(ctx, 1, next)
			if err == nil {
				t.Fatal("real disk full did not reject configuration commit")
			}
			var sqliteError interface{ Code() int }
			if !errors.As(err, &sqliteError) || sqliteError.Code()&0xff != 13 {
				t.Fatal("disk-full failure was not SQLite FULL", err)
			}
			if stage == "prepare" && (len(g.applied) != 0 || len(v.applied) != 0) {
				t.Fatal("failed prepare still applied engine configuration")
			}
			t.Logf("%s storage error: %v", stage, err)
			if g.value != old.Gateway || v.value != old.VPN {
				t.Fatal("disk-full failure left candidate engines active")
			}
			if filler == "" {
				t.Fatal("fixture did not inject actual disk pressure")
			}
			if err = os.Remove(filler); err != nil {
				t.Fatal(err)
			}
			v.onApply = nil
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			db, err = OpenJournal(ctx, path, control.Revision{Number: 99})
			if err != nil {
				t.Fatal("disk-full reopen failed", err)
			}
			coordinator := control.NewCoordinator(db, g, v)
			if err = coordinator.Recover(ctx); err != nil {
				t.Fatal("disk-full recovery failed", err)
			}
			journal, err := db.Load(ctx)
			if err != nil || journal.Pending != nil || journal.Applied != old {
				t.Fatal("disk full lost last committed revision", journal, err)
			}
			actual, err := db.Account(ctx)
			if err != nil || !reflect.DeepEqual(actual, account) {
				t.Fatal("disk full changed authentication or revived recovery code", err)
			}
			var integrity string
			if err = db.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
				t.Fatal("disk-full database integrity", integrity, err)
			}
			if err = coordinator.Apply(ctx, 1, next); err != nil {
				t.Fatal("write remained broken after freeing space", err)
			}
			journal, err = db.Load(ctx)
			if err != nil || journal.Applied != next || journal.Pending != nil || g.value != next.Gateway || v.value != next.VPN {
				t.Fatal("normal update not restored after disk pressure", err)
			}
		})
	}
}

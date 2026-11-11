//go:build integration && linux

package deployment

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/maintenance"
	"github.com/dream-until-dawn/trojan_proxy/internal/recovery"
)

func TestDisposableLiveBackupAndColdRestoreGate(t *testing.T) {
	if os.Getenv("TROJAN_DISPOSABLE_COMPOSE_TEST") != "1" {
		t.Skip("仅对探针创建的一次性卷运行")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := config.Load("/etc/trojan-proxy/proxy.json")
	if err != nil {
		t.Fatal(err)
	}
	if lock, err := maintenance.Acquire(c.DataDir, true); err != maintenance.ErrInUse {
		if lock != nil {
			lock.Close()
		}
		t.Fatal("recovery lock did not protect live control", err)
	}
	report, err := recovery.Backup(ctx, c, "/tmp/disposable-backup.tgz")
	if err != nil {
		t.Fatal("live backup failed", err)
	}
	target := c
	target.DataDir = "/restore"
	if err = recovery.Restore(ctx, target, report.Path, report.SHA256); err != nil {
		t.Fatal("disposable cold restore failed", err)
	}
	body, err := json.Marshal(target)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/tmp/restored.json", body, 0600); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, "/usr/local/bin/control", "--config", "/tmp/restored.json")
	output, err := child.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "冷还原后必须先通过SSH") {
		t.Fatal("restored controller did not block old credentials before listeners", err)
	}
}

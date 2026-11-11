package certificates

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManagerImportSelectionExpiryAndBudget(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	chain, key, roots := fixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	m := &Manager{PublishedDirectory: filepath.Join(t.TempDir(), "published"), Roots: roots, Now: func() time.Time { return now }}
	prepared, err := m.Import("probe.test", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	selection := Selection{Domain: "probe.test", Source: "imported", ImportedVersion: prepared.Version}
	m.Current = func(context.Context) (Selection, error) { return selection, nil }
	pair, err := m.Pair(selection)
	if err != nil || pair.Metadata().Fingerprint != prepared.Info.Fingerprint {
		t.Fatal("imported version not readable", err)
	}
	state, err := m.Status(context.Background())
	if err != nil || !state.Ready || state.Info == nil {
		t.Fatal("valid imported certificate not ready", state, err)
	}
	b, _ := json.Marshal(state)
	if strings.Contains(string(b), "PRIVATE KEY") || strings.Contains(string(b), m.PublishedDirectory) {
		t.Fatal("certificate state leaked material or path", string(b))
	}
	// 在发布根外准备真实有效材料，避免不存在文件掩盖版本路径校验被删除的问题。
	outside := filepath.Join(filepath.Dir(m.PublishedDirectory), "private")
	if err = os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(outside, "fullchain.pem"), chain, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(outside, "private.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Selection{{Domain: "wrong.test", Source: "imported", ImportedVersion: prepared.Version}, {Domain: "probe.test", Source: "imported", ImportedVersion: "../private"}, {Domain: "probe.test", Source: "none"}} {
		if _, err = m.Pair(bad); err == nil {
			t.Fatal("unsafe certificate selection accepted", bad)
		}
	}
	if _, err = m.Import("wrong.test", chain, key); err == nil {
		t.Fatal("wrong import domain accepted")
	}
	for i := 0; i < 63; i++ {
		if err := os.Mkdir(filepath.Join(m.PublishedDirectory, fmt.Sprintf("%064x", i)), 0750); err != nil {
			t.Fatal(err)
		}
	}
	if duplicate, err := m.Import("probe.test", chain, key); err != nil || duplicate.Version != prepared.Version {
		t.Fatal("duplicate import consumed quota", err)
	}
	// 保持同一可信链，只改变PEM尾部空白，形成不同的不可变发布版本。
	if _, err = m.Import("probe.test", append(chain, '\n'), key); err == nil {
		t.Fatal("certificate import exceeded bounded storage")
	}
	now = now.Add(2 * time.Hour)
	if _, err = m.Pair(selection); err == nil {
		t.Fatal("published certificate bypassed expiry check")
	}
	state, err = m.Status(context.Background())
	if err != nil || state.Ready || state.Info != nil {
		t.Fatal("expired certificate remained ready", state, err)
	}
}

func TestManagerLegacySourceIsDomainBound(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	chain, key, roots := fixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "fullchain.cer"), chain, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "private.key"), key, 0600); err != nil {
		t.Fatal(err)
	}
	m := &Manager{LegacyDirectory: directory, LegacyDomain: "probe.test", Roots: roots}
	if _, err := m.Pair(Selection{Domain: "probe.test", Source: "imported"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Pair(Selection{Domain: "other.test", Source: "imported"}); err == nil {
		t.Fatal("legacy source expanded to unapproved domain")
	}
}

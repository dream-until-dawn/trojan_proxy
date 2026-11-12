package main

import (
	"encoding/json"
	"errors"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/maintenance"
	"os"
	"path/filepath"
	"testing"
)

func TestFormatDowngradeRefusesLiveControlAndMissingDatabase(t *testing.T) {
	directory := t.TempDir()
	c := config.Config{Version: 1, AdminPort: 8007, ControlPort: 18090, VPNPort: 18443, DataDir: directory}
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "proxy.json")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	lock, err := maintenance.Acquire(directory, false)
	if err != nil {
		t.Fatal(err)
	}
	err = downgradeHTTPFormat(path)
	lock.Close()
	if !errors.Is(err, maintenance.ErrInUse) {
		t.Fatal("format downgrade bypassed live-control lock", err)
	}
	if err = downgradeHTTPFormat(path); err == nil {
		t.Fatal("format downgrade initialized missing database")
	}
	if _, err = os.Stat(filepath.Join(directory, "control.db")); !os.IsNotExist(err) {
		t.Fatal("missing database guard created data", err)
	}
}

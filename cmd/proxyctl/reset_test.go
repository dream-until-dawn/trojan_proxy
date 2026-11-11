package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminResetRefusesNonInteractiveSecretOutput(t *testing.T) {
	err := resetAdministrator(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "SSH交互终端") {
		t.Fatal("admin recovery allowed non-interactive output", err)
	}
}

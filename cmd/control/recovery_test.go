package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestColdRestoreCannotServeOldAuthentication(t *testing.T) {
	directory := t.TempDir()
	if err := verifyRecoveryReady(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "recovery-required"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyRecoveryReady(directory); err == nil {
		t.Fatal("cold restore allowed old authentication before rebinding")
	}
}

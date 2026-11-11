package files

import (
	"path/filepath"
	"syscall"
	"testing"
)

func TestRejectFIFO(t *testing.T) {
	directory := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(directory, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if f, err := r.Open("pipe"); err == nil {
		f.Close()
		t.Fatal("FIFO 被接受")
	}
}

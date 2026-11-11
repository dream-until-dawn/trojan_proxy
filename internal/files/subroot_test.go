package files

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSubRootCannotEscapeMountOrPublishedSubdirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "published"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "secret.txt"), []byte("private-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "published", "public.txt"), []byte("public-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	child, err := root.Sub("published")
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	file, err := child.Open("public.txt")
	if err != nil {
		t.Fatal("published subdirectory not readable", err)
	}
	file.Close()
	for _, bad := range []string{"..", "../secret.txt", directory, ".hidden", "published/../published"} {
		if opened, err := root.Sub(bad); err == nil {
			opened.Close()
			t.Fatal("subroot accepted invalid relative path", bad)
		}
	}
	// Windows环境可能没有创建符号链接权限；Linux门槛必须实际执行此断言。
	if err := os.Symlink("../secret.txt", filepath.Join(directory, "published", "escape.txt")); err != nil {
		if os.PathSeparator == '\\' {
			return
		}
		t.Fatal(err)
	}
	if file, err := child.Open("escape.txt"); err == nil {
		file.Close()
		t.Fatal("subroot symlink exposed unpublished sibling")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(directory, "outside")); err != nil {
		t.Fatal(err)
	}
	if opened, err := root.Sub("outside"); err == nil {
		opened.Close()
		t.Fatal("subroot symlink escaped authorized mount")
	}
}

package files

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestRootBoundary(t *testing.T) {
	base := t.TempDir()
	public := filepath.Join(base, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(public, "ok.txt"), []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "secret"), []byte("outside-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRoot(public)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f, err := r.Open("ok.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(b) != "public" {
		t.Fatalf("正文错误: %q %v", b, err)
	}
	for _, name := range []string{"../secret", "/etc/passwd", ".env", "a/../../secret", "%2e%2e/secret", "a\\secret", "ok.txt\x00", ".", "link/"} {
		if f, err := r.Open(name); err == nil {
			f.Close()
			t.Fatalf("非法路径被接受: %q", name)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("符号链接攻击必须在 Linux 验收")
	}
	link := filepath.Join(public, "link")
	if err := os.Symlink(filepath.Join(base, "secret"), link); err != nil {
		t.Fatal(err)
	}
	if f, err := r.Open("link"); err == nil {
		f.Close()
		t.Fatal("根外符号链接被接受")
	}
	// 不断交换合法链接和越界链接，确认不会出现检查后换链逃逸。
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			os.Remove(link)
			os.Symlink("ok.txt", link)
			os.Remove(link)
			os.Symlink(filepath.Join(base, "secret"), link)
		}
	}()
	for i := 0; i < 1000; i++ {
		f, err := r.Open("link")
		if err != nil {
			continue
		}
		b, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			t.Error(err)
		}
		if string(b) != "public" {
			t.Errorf("泄露根外数据: %q", b)
		}
	}
	wg.Wait()
}

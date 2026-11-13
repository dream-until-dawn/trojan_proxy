//go:build linux

package webaccess

import (
	"fmt"
	"os"
	"syscall"
)

func fileIdentity(f *os.File) (string, error) {
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("访问文件身份不可用")
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino), nil
}

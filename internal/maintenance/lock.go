// Package maintenance 让控制进程与离线恢复工具通过同一个卷锁协调。
package maintenance

import (
	"errors"
	"os"
	"path/filepath"
)

var ErrInUse = errors.New("控制服务或其他维护操作仍在运行，请先停止control服务")

// Lock 的共享模式保护正常控制进程，独占模式用于重置和冷还原。
type Lock struct{ file *os.File }

// Acquire 采用非阻塞卷锁，避免维护命令等待时误以为已经停止旧控制服务。
func Acquire(directory string, exclusive bool) (*Lock, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	f, err := openLock(filepath.Join(directory, "maintenance.lock"))
	if err != nil {
		return nil, err
	}
	if err = lockFile(f, exclusive); err != nil {
		f.Close()
		return nil, ErrInUse
	}
	return &Lock{file: f}, nil
}
func (l *Lock) Close() error { return l.file.Close() }

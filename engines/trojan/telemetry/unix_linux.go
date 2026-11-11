//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
package telemetry

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// ListenUnix 只移除本UID拥有且已失联的旧socket；普通文件或仍活跃的socket一律拒绝。
func ListenUnix(path string) (net.Listener, error) {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	stat, err := lock.Stat()
	if err != nil {
		lock.Close()
		return nil, err
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 || owner.Uid != uint32(os.Getuid()) {
		lock.Close()
		return nil, errors.New("统计锁文件权限或所有者异常")
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, err
	}
	retained := false
	defer func() {
		if !retained {
			syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			lock.Close()
		}
	}()
	if stat, err := os.Lstat(path); err == nil {
		if stat.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("统计socket路径不是socket")
		}
		if info, ok := stat.Sys().(*syscall.Stat_t); !ok || info.Uid != uint32(os.Getuid()) {
			return nil, errors.New("统计socket所有者不匹配")
		}
		connection, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			connection.Close()
			return nil, errors.New("统计socket仍在运行")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0660); err != nil {
		listener.Close()
		return nil, err
	}
	retained = true
	return &lockedListener{Listener: listener, lock: lock}, nil
}

type lockedListener struct {
	net.Listener
	lock *os.File
}

func (l *lockedListener) Close() error {
	err := l.Listener.Close()
	syscall.Flock(int(l.lock.Fd()), syscall.LOCK_UN)
	l.lock.Close()
	return err
}

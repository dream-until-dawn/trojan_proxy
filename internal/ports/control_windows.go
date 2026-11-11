package ports

import (
	"golang.org/x/sys/windows"
	"syscall"
)

// Windows 的普通 wildcard bind 可能与已有单地址监听共存；预检必须要求独占。
func portControl(_, _ string, conn syscall.RawConn) error {
	var optionErr error
	err := conn.Control(func(fd uintptr) {
		// Winsock 定义 SO_EXCLUSIVEADDRUSE 为按位取反 SO_REUSEADDR。
		optionErr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, ^windows.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}
	return optionErr
}

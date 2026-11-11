//go:build !windows

package ports

import "syscall"

// Linux 保持 Go 默认的端口绑定语义。
var portControl func(string, string, syscall.RawConn) error

// gateway-entry 只在启动瞬间交接身份；随后以非root和单一低端口能力替换为Caddy。
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func run(args []string) error {
	if len(args) > 0 && args[0] == "caddy" {
		args = args[1:]
	}
	if len(args) == 0 {
		args = []string{"run", "--config", "/run/caddy/bootstrap.json"}
	}
	switch args[0] {
	case "run", "validate", "version", "list-modules":
	default:
		return errors.New("网关入口只允许固定Caddy命令")
	}
	// capability属于OS线程；身份、能力交接与exec必须固定在同一线程完成。
	runtime.LockOSThread()
	if os.Geteuid() == 0 {
		if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
			return err
		}
		// 在离开root前缩窄bounding集，不能把SETUID/SETGID留给长期运行的网关。
		for capability := 0; capability < 64; capability++ {
			if capability == unix.CAP_NET_BIND_SERVICE {
				continue
			}
			if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err != nil && !errors.Is(err, syscall.EINVAL) {
				return err
			}
		}
		if err := unix.Setgroups([]int{10001}); err != nil {
			return err
		}
		if err := unix.Setresgid(10001, 10001, 10001); err != nil {
			return err
		}
		if err := unix.Setresuid(10001, 10001, 10001); err != nil {
			return err
		}
		header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
		data := [2]unix.CapUserData{}
		bit := uint32(1) << unix.CAP_NET_BIND_SERVICE
		data[0] = unix.CapUserData{Effective: bit, Permitted: bit, Inheritable: bit}
		if err := unix.Capset(&header, &data[0]); err != nil {
			return err
		}
		if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, unix.CAP_NET_BIND_SERVICE, 0, 0); err != nil {
			return err
		}
	}
	if os.Geteuid() != 10001 || os.Getegid() != 10001 {
		return errors.New("网关必须以10001:10001身份运行")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	return unix.Exec("/usr/bin/caddy", append([]string{"caddy"}, args...), os.Environ())
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "网关启动身份或能力交接失败:", err)
		os.Exit(1)
	}
}

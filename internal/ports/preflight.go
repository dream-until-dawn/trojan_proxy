// Package ports 负责只读意义上的绑定预检，不停止任何冲突进程。
package ports

import (
	"context"
	"fmt"
	"net"
)

// Check 同时尝试持有全部候选 TCP 监听，发现冲突后释放本次句柄。
// 返回成功后句柄也会释放；实际启动仍必须处理预检后的端口争抢。
func Check(ports []int) error {
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}()
	for _, port := range ports {
		for _, network := range []string{"tcp4", "tcp6"} {
			config := net.ListenConfig{Control: portControl}
			listener, err := config.Listen(context.Background(), network, net.JoinHostPort("", fmt.Sprint(port)))
			if err != nil {
				return fmt.Errorf("%s端口%d不可用: %w", network, port, err)
			}
			listeners = append(listeners, listener)
		}
	}
	return nil
}

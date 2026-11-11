//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later
package telemetry

import (
	"errors"
	"net"
)

// ListenUnix 的产品部署只支持Linux，其他平台仍可运行计数器和编译测试。
func ListenUnix(string) (net.Listener, error) {
	return nil, errors.New("统计Unix接口仅支持Linux部署")
}

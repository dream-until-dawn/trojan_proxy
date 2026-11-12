// Package adminentry 定义管理入口身份；路径与Origin分别校验，不能互相替代。
package adminentry

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Endpoint 是受信任设置推导的入口，Prefix为空表示独立端口或SSH回环根入口。
type Endpoint struct{ Origin, Prefix string }

// Identity 同时绑定Origin和管理路径，用于候选入口确认。
func (e Endpoint) Identity() string { return e.Origin + e.Prefix }

var prefixPattern = regexp.MustCompile(`^/[a-z][a-z0-9_-]*(/[a-z][a-z0-9_-]*)*$`)

// ValidatePath 不接受根路径、转义、点段、尾斜杠或基础协议保留路径。
func ValidatePath(prefix string) error {
	if prefix == "" {
		return nil
	}
	if len(prefix) > 128 || !prefixPattern.MatchString(prefix) {
		return errors.New("管理路径必须为规范小写前缀，例如/proxy，不含尾斜杠")
	}
	first := strings.Split(strings.TrimPrefix(prefix, "/"), "/")[0]
	if first == "api" || first == "healthz" {
		return errors.New("管理路径不能使用API或健康检查保留前缀")
	}
	return nil
}

// ForSite 将部署端口与管理路径投影为浏览器实际Origin。
func ForSite(domain string, adminPort, controlPort int, prefix string) Endpoint {
	if domain == "" {
		return Endpoint{Origin: "http://127.0.0.1:" + strconv.Itoa(controlPort)}
	}
	if prefix != "" {
		return Endpoint{Origin: "https://" + domain, Prefix: prefix}
	}
	return Endpoint{Origin: "https://" + net.JoinHostPort(domain, strconv.Itoa(adminPort))}
}

// Loopback 始终保留SSH隧道管理，不把公网Host映射为本机入口。
func Loopback(port int) []Endpoint {
	return []Endpoint{{Origin: "http://127.0.0.1:" + strconv.Itoa(port)}, {Origin: "http://localhost:" + strconv.Itoa(port)}}
}

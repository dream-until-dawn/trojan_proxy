// Package routes 定义与网关实现无关的结构化路由规则。
package routes

import (
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"strings"
)

// Rule 表示一条反代或公开目录规则，绝不携带原始引擎配置。
type Rule struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Port         int    `json:"port"`
	Host         string `json:"host"`
	Path         string `json:"path"`
	Kind         string `json:"kind"`
	UpstreamIP   string `json:"upstream_ip,omitempty"`
	UpstreamPort int    `json:"upstream_port,omitempty"`
	DirectoryID  string `json:"directory_id,omitempty"`
	StripPrefix  bool   `json:"strip_prefix"`
	Browse       bool   `json:"browse"`
	HTTPS        bool   `json:"https,omitempty"` // 显式开启自定义端口TLS；省略保持原有HTTP行为。
}

// Policy 描述部署阶段与受保护的端口/目录范围。
type Policy struct {
	AdminPort, ControlPort, VPNPort, FilePort int
	AllowStandardPorts                        bool
	Directories                               map[string]string
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var hostname = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidationError 只包含可安全显示给管理员的结构化规则校验原因。
type ValidationError struct{ Cause error }

func (e *ValidationError) Error() string { return e.Cause.Error() }
func (e *ValidationError) Unwrap() error { return e.Cause }

// ValidateSet 一次校验完整规则集，防止规则互相冲突或绕回公开入口。
func ValidateSet(rules []Rule, policy Policy) (validationErr error) {
	defer func() {
		if validationErr != nil {
			validationErr = &ValidationError{Cause: validationErr}
		}
	}()
	if len(rules) > 100 {
		return fmt.Errorf("规则数量最多100条")
	}
	reserved := map[int]bool{22: true, 2375: true, 2376: true, 2019: true, policy.AdminPort: true, policy.ControlPort: true, policy.ControlPort + 2: true, policy.VPNPort: true, policy.FilePort: true}
	listen := map[int]bool{80: true, 443: true}
	for _, r := range rules {
		listen[r.Port] = true
	}
	ids, matches := map[string]bool{}, map[string]bool{}
	protocols := map[int]bool{}
	for _, r := range rules {
		secure := r.HTTPS || r.Port == 443
		if previous, exists := protocols[r.Port]; exists && previous != secure {
			return fmt.Errorf("同一端口不能混用HTTP与HTTPS规则")
		}
		protocols[r.Port] = secure
		if r.HTTPS && (r.Port == 80 || r.Host == "") {
			return fmt.Errorf("HTTPS规则需要明确域名且不能监听80")
		}
		if !identifier.MatchString(r.ID) || ids[r.ID] {
			return fmt.Errorf("规则ID无效或重复")
		}
		ids[r.ID] = true
		if strings.TrimSpace(r.Name) == "" || len(r.Name) > 200 {
			return fmt.Errorf("规则名称不能为空或过长")
		}
		if r.Port < 1 || r.Port > 65535 || reserved[r.Port] {
			return fmt.Errorf("规则监听端口被保留或无效")
		}
		if r.Port == 80 || r.Port == 443 {
			if !policy.AllowStandardPorts {
				return fmt.Errorf("80/443尚未由新网关接管")
			}
		} else if r.Port < 1024 {
			return fmt.Errorf("自定义端口必须大于等于1024")
		}
		if r.Host != "" {
			if len(r.Host) > 253 || !strings.Contains(r.Host, ".") {
				return fmt.Errorf("Host格式无效")
			}
			for _, part := range strings.Split(r.Host, ".") {
				if !hostname.MatchString(part) {
					return fmt.Errorf("Host仅支持小写ASCII普通域名")
				}
			}
		}
		if !strings.HasPrefix(r.Path, "/") || path.Clean(r.Path) != r.Path || strings.ContainsAny(r.Path, "%\\?#\x00\r\n\t ") || len(r.Path) > 512 {
			return fmt.Errorf("路径前缀无效")
		}
		match := fmt.Sprintf("%d|%s|%s", r.Port, r.Host, r.Path)
		if matches[match] {
			return fmt.Errorf("监听端口、Host和路径重复")
		}
		matches[match] = true
		switch r.Kind {
		case "proxy":
			ip, err := netip.ParseAddr(r.UpstreamIP)
			if err != nil || !ip.Unmap().IsLoopback() || ip.Zone() != "" {
				return fmt.Errorf("上游仅支持宿主机回环IP")
			}
			if r.UpstreamPort < 1 || r.UpstreamPort > 65535 || reserved[r.UpstreamPort] || listen[r.UpstreamPort] {
				return fmt.Errorf("上游端口无效、受保护或形成入口循环")
			}
			if r.DirectoryID != "" {
				return fmt.Errorf("反代规则不能配置目录")
			}
		case "files":
			if !identifier.MatchString(r.DirectoryID) || policy.Directories[r.DirectoryID] == "" {
				return fmt.Errorf("目录未被显式挂载授权")
			}
			if r.UpstreamIP != "" || r.UpstreamPort != 0 {
				return fmt.Errorf("目录规则不能配置上游")
			}
		default:
			return fmt.Errorf("未知目标类型")
		}
	}
	return nil
}

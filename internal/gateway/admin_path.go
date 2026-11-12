package gateway

import (
	"errors"
	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	"net"
	"strconv"
	"strings"
)

func validateAdminPath(s Settings, ruleset []routes.Rule) error {
	if err := adminentry.ValidatePath(s.AdminPath); err != nil {
		return err
	}
	if s.AdminPath == "" {
		return nil
	}
	if s.Domain == "" || s.Ingress == nil || !s.Policy.AllowStandardPorts {
		return errors.New("管理路径需要授权域名与标准HTTPS入口")
	}
	for _, rule := range ruleset {
		if (rule.Port == 80 || rule.Port == 443) && (rule.Host == "" || rule.Host == s.Domain) && (rule.Path == s.AdminPath || strings.HasPrefix(rule.Path, s.AdminPath+"/")) {
			return errors.New("业务规则不能占用管理路径或其子路径")
		}
	}
	return nil
}

// adminPathRoute 保留原始路径交给控制面验证，不把入口身份放进可伪造的请求头。
func adminPathRoute(s Settings) map[string]any {
	return map[string]any{"match": []any{map[string]any{"host": []string{s.Domain}, "path": []string{s.AdminPath, s.AdminPath + "/*"}}}, "handle": []any{map[string]any{"handler": "reverse_proxy", "transport": internalTransport(), "upstreams": []any{map[string]any{"dial": net.JoinHostPort("127.0.0.1", strconv.Itoa(s.ControlPort))}}}}, "terminal": true}
}

func configureAdminPath(s Settings, servers map[string]any) {
	if s.AdminPath == "" {
		return
	}
	delete(servers, "admin")
	if s.Ingress.Mode == "unavailable" {
		return
	}
	server := servers["public_443"].(map[string]any)
	server["routes"] = append([]any{adminPathRoute(s)}, server["routes"].([]any)...)
}

// insertCandidatePath 在已有爬虫策略之后、旧管理与业务路由之前叠加候选。
func insertCandidatePath(server map[string]any, route map[string]any) {
	current := server["routes"].([]any)
	position := 2
	if len(current) < position {
		position = 0
	}
	merged := append([]any{}, current[:position]...)
	merged = append(merged, route)
	merged = append(merged, current[position:]...)
	server["routes"] = merged
}

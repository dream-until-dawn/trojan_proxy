package gateway

import (
	"encoding/json"
	"errors"
	"reflect"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// CompileAdminTransition 保留当前公共业务，仅叠加候选后台监听和其证书授权。
// 同端口更换域名时合并精确Host路由；候选Host不覆盖旧入口或公开规则。
func CompileAdminTransition(current, candidate Settings, ruleset []routes.Rule) (string, error) {
	if err := validateAdminPath(candidate, ruleset); err != nil {
		return "", err
	}
	if current.ControlPort != candidate.ControlPort || current.FilePort != candidate.FilePort || current.Socket != candidate.Socket {
		return "", errors.New("入口切换不能改变内控通信边界")
	}
	if candidate.AdminPort == current.Policy.VPNPort {
		return "", errors.New("候选后台不能借用当前VPN端口，请先单独迁移VPN端口")
	}
	for _, rule := range ruleset {
		if rule.Port == candidate.AdminPort || (rule.Kind == "proxy" && rule.UpstreamPort == candidate.AdminPort) {
			return "", errors.New("候选后台端口与现有业务规则冲突")
		}
	}
	oldBody, err := Compile(current, ruleset)
	if err != nil {
		return "", err
	}
	newBody, err := Compile(candidate, nil)
	if err != nil {
		return "", err
	}
	var oldConfig, newConfig map[string]any
	if err = json.Unmarshal([]byte(oldBody), &oldConfig); err != nil {
		return "", err
	}
	if err = json.Unmarshal([]byte(newBody), &newConfig); err != nil {
		return "", err
	}
	oldApps := oldConfig["apps"].(map[string]any)
	newApps := newConfig["apps"].(map[string]any)
	oldServers := oldApps["http"].(map[string]any)["servers"].(map[string]any)
	newServers := newApps["http"].(map[string]any)["servers"].(map[string]any)
	if value, ok := newServers["admin"]; ok {
		newAdmin := value.(map[string]any)
		if old, ok := oldServers["admin"]; ok && current.AdminPort == candidate.AdminPort {
			oldAdmin := old.(map[string]any)
			oldAdmin["routes"] = append(oldAdmin["routes"].([]any), newAdmin["routes"].([]any)...)
		} else {
			oldServers["candidate_admin"] = newAdmin
		}
	}
	if candidate.AdminPath != "" {
		oldPublic, ok := oldServers["public_443"].(map[string]any)
		if !ok {
			return "", errors.New("路径迁移需要当前标准HTTPS入口")
		}
		newPublic := newServers["public_443"].(map[string]any)
		oldPublic["tls_connection_policies"] = newPublic["tls_connection_policies"]
		insertCandidatePath(oldPublic, adminPathRoute(candidate))
	}
	mergeCertificates(oldApps["tls"].(map[string]any), newApps["tls"].(map[string]any))
	body, err := json.Marshal(oldConfig)
	return string(body), err
}

// 两份配置均由本模块生成，证书模块字段只能是受控数组；不接受外部模块JSON。
func mergeCertificates(current, candidate map[string]any) {
	if value, ok := candidate["certificates"]; ok {
		certificates, ok := current["certificates"].(map[string]any)
		if !ok {
			certificates = map[string]any{}
			current["certificates"] = certificates
		}
		for key, value := range value.(map[string]any) {
			certificates[key] = uniqueAppend(certificates[key], value)
		}
	}
	if value, ok := candidate["automation"]; ok {
		automation, ok := current["automation"].(map[string]any)
		if !ok {
			automation = map[string]any{}
			current["automation"] = automation
		}
		policies := value.(map[string]any)["policies"]
		automation["policies"] = uniqueAppend(automation["policies"], policies)
	}
}

func uniqueAppend(old, new any) []any {
	result, _ := old.([]any)
	for _, item := range new.([]any) {
		found := false
		for _, existing := range result {
			if reflect.DeepEqual(existing, item) {
				found = true
				break
			}
		}
		if !found {
			result = append(result, item)
		}
	}
	return result
}

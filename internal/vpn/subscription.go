package vpn

import (
	"encoding/json"
	"errors"
	"strings"
)

// WithSubscriptionDirect 保留完整节点配置，并让订阅域走DIRECT，避免旧节点失效阻断更新。
// host由管理入口白名单推导，不接受订阅请求自行指定。
func WithSubscriptionDirect(body []byte, host string) ([]byte, error) {
	if len(host) > 253 || !strings.Contains(host, ".") {
		return nil, errors.New("订阅域名无效")
	}
	for _, label := range strings.Split(host, ".") {
		if !domainFormat.MatchString(label) {
			return nil, errors.New("订阅域名无效")
		}
	}
	var profile map[string]json.RawMessage
	if err := json.Unmarshal(body, &profile); err != nil || profile == nil {
		return nil, errors.New("VPN配置格式无效")
	}
	var rules []string
	if raw, ok := profile["rules"]; !ok || json.Unmarshal(raw, &rules) != nil {
		return nil, errors.New("VPN规则格式无效")
	}
	direct := "DOMAIN," + host + ",DIRECT"
	next := []string{direct}
	for _, rule := range rules {
		if rule != direct {
			next = append(next, rule)
		}
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	profile["rules"] = encoded
	return json.MarshalIndent(profile, "", "  ")
}

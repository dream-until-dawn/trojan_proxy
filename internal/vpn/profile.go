package vpn

import (
	"errors"
	"net/netip"
)

// Profile 是已提交业务设置的运行快照；仅进入加密修订和受限Unix命令。
// 部署固定的保护端口和保护地址始终由执行器保留，不允许请求覆盖。
type Profile struct {
	Version      int      `json:"version"`
	Domain       string   `json:"domain"`
	Port         int      `json:"port"`
	AdminPort    int      `json:"admin_port"`
	OwnAddresses []string `json:"own_addresses"`
	Resolver     string   `json:"resolver"`
}

// EffectiveSettings 让编译、导出和TLS就绪检查使用同一份修订参数。
// 旧命令不携带Profile时仍使用部署值；保护地址只允许增加，不能被网页删除。
func EffectiveSettings(base Settings, desired Desired) (Settings, error) {
	if desired.Profile == nil {
		return base, nil
	}
	p := desired.Profile
	if p.Version != 1 || p.Port < 1024 || p.Port > 65535 || p.AdminPort < 1024 || p.AdminPort > 65535 || p.Port == p.AdminPort || len(p.OwnAddresses) == 0 || len(p.OwnAddresses) > 64 {
		return Settings{}, errors.New("VPN运行参数版本、端口或自身地址无效")
	}
	for _, port := range base.ReservedPorts {
		if p.Port == port || p.AdminPort == port {
			return Settings{}, errors.New("VPN运行参数占用部署保留端口")
		}
	}
	resolver, err := netip.ParseAddrPort(p.Resolver)
	if err != nil || resolver.Port() == 0 || resolver.Addr().Zone() != "" {
		return Settings{}, errors.New("VPN运行解析器必须为有效IP:端口")
	}
	result := Settings{Domain: p.Domain, Port: p.Port, Resolver: resolver, ReservedPorts: append([]int(nil), base.ReservedPorts...)}
	seen := map[netip.Addr]bool{}
	for _, value := range p.OwnAddresses {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return Settings{}, errors.New("VPN运行参数包含无效自身地址")
		}
		address = address.Unmap()
		if !seen[address] {
			seen[address] = true
			result.OwnAddresses = append(result.OwnAddresses, address)
		}
	}
	for _, address := range base.OwnAddresses {
		address = address.Unmap()
		if !seen[address] {
			seen[address] = true
			result.OwnAddresses = append(result.OwnAddresses, address)
		}
	}
	return result, nil
}

package vpn

import (
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"net/netip"
)

// SettingsFromConfig 让控制服务和runner读取同一份部署设置，避免端口、DNS或自身IP漂移。
func SettingsFromConfig(c config.Config) (Settings, error) {
	if err := c.Validate(); err != nil {
		return Settings{}, err
	}
	resolver := c.VPNResolver
	if resolver == "" {
		resolver = "9.9.9.9:53"
	}
	address, err := netip.ParseAddrPort(resolver)
	if err != nil {
		return Settings{}, err
	}
	s := Settings{Domain: c.Domain, Port: c.VPNPort, Resolver: address}
	for _, value := range c.VPNAddresses {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return Settings{}, err
		}
		s.OwnAddresses = append(s.OwnAddresses, address)
	}
	return s, nil
}

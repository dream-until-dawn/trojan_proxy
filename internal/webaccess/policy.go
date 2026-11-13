package webaccess

import (
	"errors"
	"net/netip"
	"strings"
)

// NormalizeWhitelist 拒绝隐式主机名或非法网络，统一IPv4映射地址与网络边界。
func NormalizeWhitelist(values []string) ([]string, error) {
	if len(values) > 128 {
		return nil, errors.New("白名单最多128个IP或CIDR")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		var prefix netip.Prefix
		if strings.Contains(value, "/") {
			p, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, errors.New("白名单IP或CIDR无效")
			}
			prefix = p
		} else {
			ip, err := netip.ParseAddr(value)
			if err != nil || ip.Zone() != "" {
				return nil, errors.New("白名单只接受IP或CIDR")
			}
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return nil, errors.New("映射IPv4网络范围无效")
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		value = prefix.Masked().String()
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result, nil
}

// whitelistSQL 只拼接固定SQL结构；所有网络边界均作为BLOB参数绑定。
func whitelistSQL(cidrs []string) (string, []any) {
	parts := []string{}
	args := []any{}
	for _, value := range cidrs {
		p, _ := netip.ParsePrefix(value)
		p = p.Masked()
		low := p.Addr().As16()
		high := low
		bits := p.Bits()
		family := 6
		if p.Addr().Is4() {
			family = 4
			bits += 96
		}
		for bit := bits; bit < 128; bit++ {
			high[bit/8] |= 1 << uint(7-bit%8)
		}
		parts = append(parts, "(family=? AND address>=? AND address<=?)")
		args = append(args, family, append([]byte(nil), low[:]...), append([]byte(nil), high[:]...))
	}
	if len(parts) == 0 {
		return "0", args
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}

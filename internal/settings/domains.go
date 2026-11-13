package settings

import (
	"errors"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
)

// ValidateDomains 仅允许显式登记的主站子域；列表不接受通配符或隐式Host签发。
func ValidateDomains(site Site) error {
	if len(site.Domains) > 20 {
		return errors.New("附加域名最多20个")
	}
	seen := map[string]bool{site.Domain: true}
	for _, name := range site.Domains {
		if site.Domain == "" || len(name) > 253 || name != strings.ToLower(name) || !strings.HasSuffix(name, "."+site.Domain) || seen[name] {
			return errors.New("附加域名须为主站的唯一规范子域名")
		}
		for _, part := range strings.Split(name, ".") {
			if !domainLabel.MatchString(part) {
				return errors.New("附加域名格式无效")
			}
		}
		seen[name] = true
	}
	if site.AdminDomain != "" {
		if site.AdminDomain == site.Domain || !seen[site.AdminDomain] || site.AdminPath != "" {
			return errors.New("独立后台域名必须先登记，且不能同时使用管理路径")
		}
	}
	return nil
}

// AdminEndpoint 保留主站/VPN身份，仅将独立后台投影为443根入口。
func AdminEndpoint(site Site, controlPort int) adminentry.Endpoint {
	if site.AdminDomain != "" {
		return adminentry.Endpoint{Origin: "https://" + site.AdminDomain}
	}
	return adminentry.ForSite(site.Domain, site.AdminPort, controlPort, site.AdminPath)
}

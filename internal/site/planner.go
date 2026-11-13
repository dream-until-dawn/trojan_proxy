// Package site 连接业务设置、证书与协议适配，不向网页暴露引擎配置。
package site

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

// Planner 只使用受信任的来源与版本发布器，不读取HTTP传入的文件路径。
type Planner struct {
	View         *settings.View
	Certificates *certificates.Manager
	VPNBase      vpn.Settings
	Key          []byte
}

// Selection 将业务模型投影为只含来源和版本的证书选择。
func Selection(site settings.Site) certificates.Selection {
	return certificates.Selection{Domain: site.Domain, Source: site.CertificateSource, ImportedVersion: site.ImportedVersion}
}

// RuntimeProfile 复制可变参数，避免调用者修改草稿影响已生成的命令。
func RuntimeProfile(site settings.Site) *vpn.Profile {
	return &vpn.Profile{Version: 1, Domain: site.Domain, Port: site.VPNPort, AdminPort: site.AdminPort, OwnAddresses: append([]string(nil), site.VPNAddresses...), Resolver: site.VPNResolver}
}

// Ingress 推导就绪状态；手工来源失效不能偷偷改成自动签发。
func (p *Planner) Ingress(_ context.Context, site settings.Site) (*gateway.Ingress, error) {
	if site.Domain == "" {
		return &gateway.Ingress{Mode: "reserved"}, nil
	}
	if p.Certificates == nil {
		return nil, errors.New("证书管理未连接")
	}
	pair, err := p.Certificates.Pair(Selection(site))
	if site.CertificateSource == "automatic" {
		return &gateway.Ingress{Mode: "automatic", AwaitCertificate: err != nil, ACMEEmail: site.ACMEEmail}, nil
	}
	if site.CertificateSource != "imported" {
		return nil, errors.New("证书来源无效")
	}
	if err != nil {
		return &gateway.Ingress{Mode: "unavailable"}, nil
	}
	prepared, err := certificates.Prepare(p.Certificates.PublishedDirectory, pair)
	if err != nil {
		return nil, err
	}
	// 控制服务与网关可以使用不同挂载路径，网关侧只引用固定的发布卷位置。
	root := "/certificates/" + prepared.Version + "/"
	return &gateway.Ingress{Mode: "manual", Certificate: root + "fullchain.pem", Key: root + "private.key"}, nil
}

// DomainIngress 附加域名独立使用HTTP-01；缓存未就绪只影响该域的业务开放。
func (p *Planner) DomainIngress(_ context.Context, domain, email string) (*gateway.Ingress, error) {
	if p.Certificates == nil {
		return nil, errors.New("证书管理未连接")
	}
	_, err := p.Certificates.Pair(certificates.Selection{Domain: domain, Source: "automatic"})
	return &gateway.Ingress{Mode: "automatic", AwaitCertificate: err != nil, ACMEEmail: email}, nil
}

func revisionRules(revision control.Revision) ([]routes.Rule, error) {
	if revision.Rules == "" {
		return nil, nil
	}
	var ruleset []routes.Rule
	if err := json.Unmarshal([]byte(revision.Rules), &ruleset); err != nil {
		return nil, err
	}
	return ruleset, nil
}

// Dual 只开放候选管理入口；业务、VPN口令和VPN运行参数保留当前修订。
func (p *Planner) Dual(ctx context.Context, current, candidate settings.Site, revision control.Revision) (settings.Plan, error) {
	desired, err := vpn.Open(p.Key, revision.VPN)
	if err != nil {
		return settings.Plan{}, err
	}
	if desired.Enabled && candidate.Domain == "" {
		return settings.Plan{}, &settings.ValidationError{Cause: errors.New("请先停用VPN，再切换为无域名模式")}
	}
	if desired.Enabled {
		desired.Profile = RuntimeProfile(candidate)
		if _, err = vpn.CompileTrojan(p.VPNBase, desired); err != nil {
			return settings.Plan{}, &settings.ValidationError{Cause: err}
		}
	}
	if err := p.View.CheckDirectories(candidate); err != nil {
		return settings.Plan{}, &settings.ValidationError{Cause: err}
	}
	old, err := p.View.ForSite(ctx, current)
	if err != nil {
		return settings.Plan{}, err
	}
	next, err := p.View.ForSite(ctx, candidate)
	if err != nil {
		return settings.Plan{}, err
	}
	if candidate.CertificateSource == "imported" && candidate.Domain != "" {
		if _, err = p.Certificates.Pair(Selection(candidate)); err != nil {
			return settings.Plan{}, &settings.ValidationError{Cause: errors.New("请先导入候选域名的有效可信证书")}
		}
	}
	ruleset, err := revisionRules(revision)
	if err != nil {
		return settings.Plan{}, err
	}
	// 提前验证确认后的规则兼容性，但此时绝不应用候选公共路由。
	if _, err = gateway.Compile(next, ruleset); err != nil {
		return settings.Plan{}, &settings.ValidationError{Cause: err}
	}
	body, err := gateway.CompileAdminTransition(old, next, ruleset)
	if err != nil {
		return settings.Plan{}, &settings.ValidationError{Cause: err}
	}
	digest := sha256.Sum256([]byte("dual-entry-v1\x00" + body))
	return settings.Plan{Gateway: body, VPN: revision.VPN, Fingerprint: hex.EncodeToString(digest[:])}, nil
}

// Ready 只有证书已重新校验且目录仍可安全打开时才允许确认。
func (p *Planner) Ready(_ context.Context, site settings.Site) error {
	if err := p.View.CheckDirectories(site); err != nil {
		return err
	}
	if site.Domain == "" {
		return nil
	}
	if p.Certificates == nil {
		return errors.New("证书管理未连接")
	}
	_, err := p.Certificates.Pair(Selection(site))
	if err == nil && site.AdminDomain != "" {
		_, err = p.Certificates.Pair(certificates.Selection{Domain: site.AdminDomain, Source: "automatic"})
	}
	return err
}

// Steady 同时编译网关和加密VPN命令；协调器负责应用及失败恢复。
func (p *Planner) Steady(ctx context.Context, site settings.Site, revision control.Revision) (settings.Plan, error) {
	if err := p.Ready(ctx, site); err != nil {
		return settings.Plan{}, err
	}
	s, err := p.View.ForSite(ctx, site)
	if err != nil {
		return settings.Plan{}, err
	}
	ruleset, err := revisionRules(revision)
	if err != nil {
		return settings.Plan{}, err
	}
	body, err := gateway.Compile(s, ruleset)
	if err != nil {
		return settings.Plan{}, err
	}
	fingerprint, err := gateway.Fingerprint(s)
	if err != nil {
		return settings.Plan{}, err
	}
	sealed, err := p.vpnPlan(site, revision.VPN)
	return settings.Plan{Gateway: body, VPN: sealed, Fingerprint: fingerprint}, err
}

func (p *Planner) vpnPlan(site settings.Site, previous string) (string, error) {
	d, err := vpn.Open(p.Key, previous)
	if err != nil {
		return "", err
	}
	if !d.Enabled {
		return previous, nil
	}
	before := vpn.CommandFingerprint(d)
	if site.Domain == "" {
		return "", errors.New("请先停用VPN，再切换为无域名模式")
	}
	pair, err := p.Certificates.Pair(Selection(site))
	if err != nil {
		return "", err
	}
	prepared, err := certificates.Prepare(p.Certificates.PublishedDirectory, pair)
	if err != nil {
		return "", err
	}
	d.CertificateVersion = prepared.Version
	d.Profile = RuntimeProfile(site)
	if _, err = vpn.CompileTrojan(p.VPNBase, d); err != nil {
		return "", err
	}
	if vpn.CommandFingerprint(d) == before {
		return previous, nil
	}
	return vpn.Seal(p.Key, d)
}

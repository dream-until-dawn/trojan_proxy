package site

import (
	"context"

	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

// AdoptLegacy 只补齐旧证书与旧命令的不可变引用，不变更监听、规则或口令。
// 完成后重建容器或修改旧JSON不会再次改变这些业务值。
func (p *Planner) AdoptLegacy(ctx context.Context, store control.Store, coordinator *control.Coordinator) error {
	j, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if j.Pending != nil {
		return settings.ErrPending
	}
	d, err := settings.Decode(j.Applied.Settings, p.View.Deployment)
	if err != nil {
		return err
	}
	// 候选入口已经创建时不穿插迁移；确认或撤回后再补齐，期限照常恢复。
	if d.Pending != nil {
		return nil
	}
	desired, err := vpn.Open(p.Key, j.Applied.VPN)
	if err != nil {
		return err
	}
	changed := false
	if d.Site.CertificateSource == "imported" && d.Site.ImportedVersion == "" {
		pair, err := p.Certificates.Pair(Selection(d.Site))
		if err != nil {
			// 旧材料失效时允许网关进入HTTP保留模式，不能用迁移重试阻断后台修复。
			return nil
		}
		prepared, err := certificates.Prepare(p.Certificates.PublishedDirectory, pair)
		if err != nil {
			return err
		}
		d.Site.ImportedVersion = prepared.Version
		changed = true
	}
	if desired.Enabled && desired.Profile == nil {
		desired.Profile = RuntimeProfile(d.Site)
		if _, err = vpn.CompileTrojan(p.VPNBase, desired); err != nil {
			return err
		}
		changed = true
	}
	if !changed {
		return nil
	}
	body, err := d.Encode(p.View.Deployment)
	if err != nil {
		return err
	}
	next := j.Applied
	next.Number++
	next.Settings = body
	// 只在命令确实缺少快照时重封装，避免单纯证书引用迁移重启正在运行的VPN。
	previous, err := vpn.Open(p.Key, j.Applied.VPN)
	if err != nil {
		return err
	}
	if vpn.CommandFingerprint(previous) != vpn.CommandFingerprint(desired) {
		next.VPN, err = vpn.Seal(p.Key, desired)
		if err != nil {
			return err
		}
	}
	return coordinator.Apply(ctx, j.Applied.Number, next)
}

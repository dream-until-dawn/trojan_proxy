package settings

import (
	"context"
	"errors"
	"path"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/files"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

// View 把持久设置投影到各组件；挂载根和socket来自部署，网页不能替换。
type View struct {
	Store      control.Store
	Deployment config.Config
	Roots      map[string]*files.Root
	Standard   bool
	Ingress    func(context.Context, Site) (*gateway.Ingress, error)
	Now        func() time.Time
}

func (v *View) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Read 在迁移完成后只读取数据库；损坏或缺失设置均不退回旧文件。
func (v *View) Read(ctx context.Context) (Document, error) {
	j, err := v.Store.Load(ctx)
	if err != nil {
		return Document{}, err
	}
	return Decode(j.Applied.Settings, v.Deployment)
}

// Project 合并受信任部署边界；目录路径仅供规则校验，不用于重新打开宿主路径。
func (v *View) Project(site Site) (config.Config, error) {
	if err := (Document{Version: 1, Site: site}).Validate(v.Deployment); err != nil {
		return config.Config{}, err
	}
	c := v.Deployment
	c.Domain, c.AdminPort, c.VPNPort = site.Domain, site.AdminPort, site.VPNPort
	c.VPNAddresses = append([]string(nil), site.VPNAddresses...)
	c.VPNResolver = site.VPNResolver
	c.PublicDirectories = map[string]string{}
	for _, binding := range site.Directories {
		c.PublicDirectories[binding.ID] = path.Join(v.Deployment.PublicDirectories[binding.Root], binding.Relative)
	}
	return c, nil
}

// ForSite 生成受限网关参数；证书来源和就绪状态由可信证书适配器决定。
func (v *View) ForSite(ctx context.Context, site Site) (gateway.Settings, error) {
	c, err := v.Project(site)
	if err != nil {
		return gateway.Settings{}, err
	}
	result := gateway.Settings{Domain: c.Domain, AdminPath: site.AdminPath, AdminPort: c.AdminPort, ControlPort: c.ControlPort, FilePort: c.ControlPort + 1, Socket: "/run/caddy/admin.sock",
		Policy: routes.Policy{AdminPort: c.AdminPort, ControlPort: c.ControlPort, FilePort: c.ControlPort + 1, VPNPort: c.VPNPort, Directories: c.PublicDirectories, AllowStandardPorts: v.Standard}}
	if v.Standard {
		result.AccessLog = true
		if v.Ingress == nil {
			return gateway.Settings{}, errors.New("标准入口证书适配器未连接")
		}
		result.Ingress, err = v.Ingress(ctx, site)
		if err != nil {
			return gateway.Settings{}, err
		}
		if result.Ingress == nil {
			return gateway.Settings{}, errors.New("标准入口不能降级为阶段性后台")
		}
	}
	return result, nil
}

// Gateway 兼容routing.SettingsProvider，临时入口时保留原始双入口快照。
func (v *View) Gateway(ctx context.Context, revision control.Revision) (gateway.Settings, bool, error) {
	d, err := Decode(revision.Settings, v.Deployment)
	if err != nil {
		return gateway.Settings{}, false, err
	}
	settings, err := v.ForSite(ctx, d.Site)
	return settings, d.Pending != nil, err
}

// Origins 每次返回新映射；候选入口到期立即失效，不依赖恢复协程及时执行。
func (v *View) Origins(ctx context.Context) (map[string]bool, error) {
	endpoints, err := v.Endpoints(ctx)
	if err != nil {
		return nil, err
	}
	result := map[string]bool{}
	for _, endpoint := range endpoints {
		result[endpoint.Origin] = true
	}
	return result, nil
}

// Endpoints 只投影当前及未到期候选，避免Origin相同却路径已撤销时继续访问。
func (v *View) Endpoints(ctx context.Context) ([]adminentry.Endpoint, error) {
	d, err := v.Read(ctx)
	if err != nil {
		return nil, err
	}
	result := adminentry.Loopback(v.Deployment.ControlPort)
	add := func(site Site) {
		if site.Domain != "" {
			result = append(result, adminentry.ForSite(site.Domain, site.AdminPort, v.Deployment.ControlPort, site.AdminPath))
		}
	}
	add(d.Site)
	if d.Pending != nil && v.now().Unix() < d.Pending.Deadline {
		add(d.Pending.Candidate)
	}
	return result, nil
}

// Directory 按当前已提交绑定获取独立子根；待确认候选不能提前公开文件。
func (v *View) Directory(ctx context.Context, id string) (*files.Root, error) {
	d, err := v.Read(ctx)
	if err != nil {
		return nil, err
	}
	for _, binding := range d.Site.Directories {
		if binding.ID != id {
			continue
		}
		root := v.Roots[binding.Root]
		if root == nil {
			return nil, errors.New("发布目录挂载不可用")
		}
		return root.Sub(binding.Relative)
	}
	return nil, errors.New("发布目录未绑定")
}

// CheckDirectories 在候选计划校验时拒绝不存在、逃逸或未挂载的目录。
func (v *View) CheckDirectories(site Site) error {
	if _, err := v.Project(site); err != nil {
		return err
	}
	for _, binding := range site.Directories {
		root := v.Roots[binding.Root]
		if root == nil {
			return errors.New("发布目录挂载不可用")
		}
		child, err := root.Sub(binding.Relative)
		if err != nil {
			return errors.New("发布目录不存在或不在授权范围内")
		}
		child.Close()
	}
	return nil
}

package main

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/api"
	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/files"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	"github.com/dream-until-dawn/trojan_proxy/internal/routing"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/site"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpnrunner"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpnservice"
)

// management 在启动时连接依赖；迁移与故障恢复失败不阻断独立SSH登录服务。
type management struct {
	API         *api.Server
	Router      *routing.Service
	VPN         *vpnservice.Service
	Settings    *settings.Manager
	View        *settings.View
	coordinator *control.Coordinator
	store       control.Store
	deployment  config.Config
	planner     *site.Planner
}

func loopbackOrigins(port int) map[string]bool {
	value := strconv.Itoa(port)
	return map[string]bool{"http://127.0.0.1:" + value: true, "http://localhost:" + value: true}
}

func newManagement(c config.Config, store control.Store, key []byte, roots map[string]*files.Root) (*management, error) {
	compiled := gateway.Settings{Domain: c.Domain, AdminPort: c.AdminPort, ControlPort: c.ControlPort, FilePort: c.ControlPort + 1, Socket: "/run/caddy/admin.sock", Policy: routes.Policy{AdminPort: c.AdminPort, ControlPort: c.ControlPort, FilePort: c.ControlPort + 1, VPNPort: c.VPNPort, Directories: c.PublicDirectories}}
	engine := gateway.NewClient(compiled.Socket)
	origins := loopbackOrigins(c.ControlPort)
	if c.Domain != "" {
		origins["https://"+net.JoinHostPort(c.Domain, strconv.Itoa(c.AdminPort))] = true
	}
	m := &management{API: &api.Server{Origins: origins}, store: store, deployment: c}
	if !c.VPNManagement && !c.StandardIngress {
		m.Router = routing.NewService(store, engine, compiled)
		m.API.Routes = m.Router
		return m, nil
	}
	base, err := vpn.SettingsFromConfig(c)
	if err != nil {
		return nil, err
	}
	runner := vpnrunner.NewClient("/run/vpn/control.sock")
	component := &vpnrunner.Component{Key: key, Runner: runner}
	m.coordinator = control.NewCoordinator(store, engine, component)
	options := vpnservice.Options{Settings: base, Key: key, PublishedDirectory: "/certificates", Source: func() (certificates.Pair, error) {
		return certificates.ReadPairFiles("/certs/fullchain.cer", "/certs/private.key", c.Domain, time.Now(), nil)
	}}
	if c.StandardIngress {
		m.View = &settings.View{Store: store, Deployment: c, Roots: roots, Standard: true}
		certificateManager := &certificates.Manager{PublishedDirectory: "/certificates", ManagedDirectory: "/caddy-data/caddy/certificates", LegacyDirectory: "/certs", LegacyDomain: c.Domain}
		certificateManager.Current = func(ctx context.Context) (certificates.Selection, error) {
			d, err := m.View.Read(ctx)
			if err != nil {
				return certificates.Selection{}, err
			}
			return site.Selection(d.Site), nil
		}
		planner := &site.Planner{View: m.View, Certificates: certificateManager, VPNBase: base, Key: append([]byte(nil), key...)}
		m.planner = planner
		m.View.Ingress = planner.Ingress
		m.Settings = settings.NewManager(store, m.coordinator, planner, c)
		m.Router = routing.NewServiceWithProvider(store, engine, compiled, m.coordinator, m.View.Gateway)
		guard := func(ctx context.Context) error { return settings.RequireStable(ctx, store, c) }
		options.WriteGuard = guard
		options.ProfileSource = func(ctx context.Context) (*vpn.Profile, error) {
			d, err := m.View.Read(ctx)
			if err != nil {
				return nil, err
			}
			return site.RuntimeProfile(d.Site), nil
		}
		options.Source = func() (certificates.Pair, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			selection, err := certificateManager.Current(ctx)
			if err != nil {
				return certificates.Pair{}, err
			}
			return certificateManager.Pair(selection)
		}
		m.API.Settings = m.Settings
		m.API.Certificates = certificateManager
		m.API.WriteGuard = guard
		m.API.OriginProvider = func() map[string]bool {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result, err := m.View.Origins(ctx)
			if err != nil {
				return loopbackOrigins(c.ControlPort)
			}
			return result
		}
	} else {
		m.Router = routing.NewServiceWithCoordinator(store, engine, compiled, m.coordinator)
	}
	m.VPN = vpnservice.NewService(store, m.coordinator, runner, options)
	component.CertificateValid = m.VPN.CertificateValid
	m.API.Routes = m.Router
	m.API.VPN = m.VPN
	return m, nil
}

// Prepare 先恢复完整事务再导入一次旧配置，避免每次重启把JSON写回网页设置。
func (m *management) Prepare(ctx context.Context) error {
	if m.Settings == nil {
		return nil
	}
	if err := m.coordinator.Recover(ctx); err != nil {
		return err
	}
	if _, err := settings.EnsureImported(ctx, m.store, m.coordinator, m.deployment); err != nil {
		return err
	}
	if err := m.Settings.Reconcile(ctx); err != nil {
		return err
	}
	return m.planner.AdoptLegacy(ctx, m.store, m.coordinator)
}

// Package routing 将结构化规则、网关编译与持久化修订协调起来。
package routing

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

// Gateway 提供完整快照读取及受控原子应用。
type Gateway interface {
	control.Component
	Current(context.Context) (string, error)
}

type unchangedVPN struct{}

func (unchangedVPN) Check(_ context.Context, value string) error {
	if value != "" {
		return errors.New("VPN适配器尚未启用，拒绝改变其配置")
	}
	return nil
}
func (v unchangedVPN) Apply(ctx context.Context, value string) error { return v.Check(ctx, value) }

// Service 的首次使用先恢复日志并收敛网关，不把容器重启当成配置丢失。
type Service struct {
	mu          sync.Mutex
	store       control.Store
	gateway     Gateway
	settings    gateway.Settings
	coordinator *control.Coordinator
	ready       bool
	provider    SettingsProvider
	frozen      bool
}

// SettingsProvider 只解析同一完整修订；第二个返回值表示临时入口尚待确认。
type SettingsProvider func(context.Context, control.Revision) (gateway.Settings, bool, error)

var ErrWriteFrozen = errors.New("入口等待确认，禁止修改路由")

// NewServiceWithProvider 从持久修订读取设置，避免重启或自动收敛覆盖网页配置。
func NewServiceWithProvider(store control.Store, engine Gateway, fallback gateway.Settings, coordinator *control.Coordinator, provider SettingsProvider) *Service {
	s := NewServiceWithCoordinator(store, engine, fallback, coordinator)
	s.provider = provider
	return s
}

func (s *Service) refreshSettings(ctx context.Context, revision control.Revision) error {
	if s.provider == nil {
		return nil
	}
	next, frozen, err := s.provider(ctx, revision)
	if err != nil {
		return err
	}
	previousHash, err := gateway.Fingerprint(s.settings)
	if err != nil {
		return err
	}
	nextHash, err := gateway.Fingerprint(next)
	if err != nil {
		return err
	}
	if previousHash != nextHash || s.frozen != frozen {
		s.ready = false
	}
	s.settings, s.frozen = next, frozen
	return nil
}

// Snapshot 是后台可读取的规则状态，不包括引擎原始配置和证书路径。
type Snapshot struct {
	Revision        uint64        `json:"revision"`
	Rules           []routes.Rule `json:"rules"`
	Pending         bool          `json:"pending"`
	Directories     []string      `json:"directories"`
	StandardIngress bool          `json:"standard_ingress"`
}

// NewService 只连接依赖；初始化失败会阻止业务修改但不影响独立登录入口。
func NewService(store control.Store, engine Gateway, settings gateway.Settings) *Service {
	return NewServiceWithCoordinator(store, engine, settings, control.NewCoordinator(store, engine, unchangedVPN{}))
}

// NewServiceWithCoordinator 让证书、VPN和路由共享同一协调锁，避免跨功能并发提交。
func NewServiceWithCoordinator(store control.Store, engine Gateway, settings gateway.Settings, coordinator *control.Coordinator) *Service {
	return &Service{store: store, gateway: engine, settings: settings, coordinator: coordinator}
}

func (s *Service) initialize(ctx context.Context) error {
	if s.provider != nil {
		j, err := s.store.Load(ctx)
		if err != nil {
			return err
		}
		if err = s.refreshSettings(ctx, j.Applied); err != nil {
			return err
		}
	}
	if s.ready {
		return nil
	}
	digest, err := gateway.Fingerprint(s.settings)
	if err != nil {
		return err
	}
	j, err := s.store.Load(ctx)
	if err != nil {
		return err
	}
	if j.Applied.Gateway == "" && j.Pending == nil {
		current, err := s.gateway.Current(ctx)
		if err != nil {
			return err
		}
		j.Applied.Gateway = current
		j.Applied.Rules = "[]"
		j.Applied.GatewaySettings = digest
		if err = s.store.Save(ctx, j); err != nil {
			return err
		}
	}
	if err = s.coordinator.Recover(ctx); err != nil {
		return err
	}
	j, err = s.store.Load(ctx)
	if err != nil {
		return err
	}
	if err = s.refreshSettings(ctx, j.Applied); err != nil {
		return err
	}
	digest, err = gateway.Fingerprint(s.settings)
	if err != nil {
		return err
	}
	if !s.frozen && j.Applied.GatewaySettings != digest {
		// 部署设置或编译安全策略变化必须形成完整修订，不能在重启后被旧JSON覆盖。
		var ruleset []routes.Rule
		if j.Applied.Rules != "" {
			if err = json.Unmarshal([]byte(j.Applied.Rules), &ruleset); err != nil {
				return err
			}
		}
		compiled, err := gateway.Compile(s.settings, ruleset)
		if err != nil {
			return err
		}
		next := j.Applied
		next.Number++
		next.Gateway = compiled
		next.GatewaySettings = digest
		if err = s.coordinator.Apply(ctx, j.Applied.Number, next); err != nil {
			return err
		}
		j.Applied = next
	}
	// 网关独立重启后可能只加载部署文件，必须恢复数据库里的已提交配置。
	if err = s.coordinator.ReconcileGateway(ctx); err != nil {
		return err
	}
	s.ready = true
	return nil
}

// List 只返回已提交业务规则；恢复失败不会返回虚假的空配置。
func (s *Service) List(ctx context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.initialize(ctx); err != nil {
		return Snapshot{}, err
	}
	j, err := s.store.Load(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	state := Snapshot{Revision: j.Applied.Number, Rules: []routes.Rule{}, Pending: j.Pending != nil || s.frozen, StandardIngress: s.settings.Ingress != nil}
	state.Directories = []string{}
	for id := range s.settings.Policy.Directories {
		state.Directories = append(state.Directories, id)
	}
	sort.Strings(state.Directories)
	if j.Applied.Rules != "" {
		if err = json.Unmarshal([]byte(j.Applied.Rules), &state.Rules); err != nil {
			return Snapshot{}, err
		}
	}
	return state, nil
}

// Apply 校验完整目标规则集，保留后台入口并使用修订号避免覆盖他人改动。
func (s *Service) Apply(ctx context.Context, expected uint64, ruleset []routes.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.initialize(ctx); err != nil {
		return err
	}
	j, err := s.store.Load(ctx)
	if err != nil {
		return err
	}
	if j.Applied.Number != expected {
		return control.ErrRevisionConflict
	}
	if err = s.refreshSettings(ctx, j.Applied); err != nil {
		return err
	}
	if s.frozen {
		return ErrWriteFrozen
	}
	if err = routes.ValidateSet(ruleset, s.settings.Policy); err != nil {
		return err
	}
	config, err := gateway.Compile(s.settings, ruleset)
	if err != nil {
		return err
	}
	body, err := json.Marshal(ruleset)
	if err != nil {
		return err
	}
	next := j.Applied
	next.Number = expected + 1
	next.Gateway = config
	next.Rules = string(body)
	if err = s.coordinator.Apply(ctx, expected, next); err != nil {
		s.ready = false
		return err
	}
	return nil
}

// PublicRule 不触发网关操作，只返回已提交的公开目录规则。
func (s *Service) PublicRule(ctx context.Context, id string) (routes.Rule, error) {
	j, err := s.store.Load(ctx)
	if err != nil {
		return routes.Rule{}, err
	}
	var ruleset []routes.Rule
	if j.Applied.Rules == "" {
		return routes.Rule{}, errors.New("没有已提交规则")
	}
	if err = json.Unmarshal([]byte(j.Applied.Rules), &ruleset); err != nil {
		return routes.Rule{}, err
	}
	for _, rule := range ruleset {
		if rule.ID == id && rule.Kind == "files" {
			return rule, nil
		}
	}
	return routes.Rule{}, errors.New("公开规则不存在")
}

// Reconcile 在启动与网关独立重启后重新核对实际配置；失败不扩大为登录服务故障。
func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider != nil {
		j, err := s.store.Load(ctx)
		if err != nil {
			return err
		}
		if err = s.refreshSettings(ctx, j.Applied); err != nil {
			return err
		}
	}
	if s.ready {
		j, err := s.store.Load(ctx)
		if err != nil {
			return err
		}
		actual, err := s.gateway.Current(ctx)
		if err != nil {
			s.ready = false
			return err
		}
		var actualValue, expectedValue any
		if json.Unmarshal([]byte(actual), &actualValue) != nil || json.Unmarshal([]byte(j.Applied.Gateway), &expectedValue) != nil {
			return errors.New("网关快照无法解析")
		}
		if j.Pending == nil && reflect.DeepEqual(actualValue, expectedValue) {
			return nil
		}
		s.ready = false
	}
	return s.initialize(ctx)
}

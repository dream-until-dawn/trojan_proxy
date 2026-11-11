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
}

// Snapshot 是后台可读取的规则状态，不包括引擎原始配置和证书路径。
type Snapshot struct {
	Revision    uint64        `json:"revision"`
	Rules       []routes.Rule `json:"rules"`
	Pending     bool          `json:"pending"`
	Directories []string      `json:"directories"`
}

// NewService 只连接依赖；初始化失败会阻止业务修改但不影响独立登录入口。
func NewService(store control.Store, engine Gateway, settings gateway.Settings) *Service {
	return &Service{store: store, gateway: engine, settings: settings, coordinator: control.NewCoordinator(store, engine, unchangedVPN{})}
}

func (s *Service) initialize(ctx context.Context) error {
	if s.ready {
		return nil
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
	// 网关独立重启后可能只加载部署文件，必须恢复数据库里的已提交配置。
	if err = s.gateway.Apply(ctx, j.Applied.Gateway); err != nil {
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
	state := Snapshot{Revision: j.Applied.Number, Rules: []routes.Rule{}, Pending: j.Pending != nil}
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
	if err := routes.ValidateSet(ruleset, s.settings.Policy); err != nil {
		return err
	}
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
	config, err := gateway.Compile(s.settings, ruleset)
	if err != nil {
		return err
	}
	body, err := json.Marshal(ruleset)
	if err != nil {
		return err
	}
	next := control.Revision{Number: expected + 1, Gateway: config, VPN: j.Applied.VPN, Rules: string(body)}
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

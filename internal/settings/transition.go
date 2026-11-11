package settings

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

var (
	ErrFrozen       = errors.New("入口等待确认，暂时禁止其他业务修改")
	ErrConfirmation = errors.New("请在期限内从新后台入口登录并确认，且证书必须就绪")
)

// Plan 同时描述网关及VPN的目标；原始文本只存在内部编译边界。
type Plan struct{ Gateway, VPN, Fingerprint string }

// Planner 必须编译并验证受限引擎配置，不能返回Web提供的原始JSON。
type Planner interface {
	Dual(context.Context, Site, Site, control.Revision) (Plan, error)
	Steady(context.Context, Site, control.Revision) (Plan, error)
	Ready(context.Context, Site) error
}

// Manager 的短锁保护入口转换；完整修订冲突仍由共享协调器与存储层拒绝。
type Manager struct {
	mu          sync.Mutex
	store       control.Store
	coordinator *control.Coordinator
	planner     Planner
	deployment  config.Config
	now         func() time.Time
}

// NewManager 不自动改变入口，调用前必须完成单次设置迁移。
func NewManager(store control.Store, coordinator *control.Coordinator, planner Planner, deployment config.Config) *Manager {
	return &Manager{store: store, coordinator: coordinator, planner: planner, deployment: deployment, now: time.Now}
}

// Snapshot 排除原始配置、密文和回滚路径，适合近期认证后的管理接口。
type Snapshot struct {
	Revision        uint64   `json:"revision"`
	Site            Site     `json:"site"`
	Candidate       *Site    `json:"candidate,omitempty"`
	Deadline        int64    `json:"deadline,omitempty"`
	CurrentOrigin   string   `json:"current_origin"`
	CandidateOrigin string   `json:"candidate_origin,omitempty"`
	Mounts          []string `json:"mounts"`
}

func (m *Manager) load(ctx context.Context) (control.Journal, Document, error) {
	j, err := m.store.Load(ctx)
	if err != nil {
		return j, Document{}, err
	}
	if j.Pending != nil {
		return j, Document{}, ErrPending
	}
	d, err := Decode(j.Applied.Settings, m.deployment)
	return j, d, err
}

// Status 返回已提交的当前设置和候选入口，不能把临时配置当作已确认结果。
func (m *Manager) Status(ctx context.Context) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, d, err := m.load(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	result := Snapshot{Revision: j.Applied.Number, Site: d.Site, CurrentOrigin: m.candidateOrigin(d.Site), Mounts: []string{}}
	for id := range m.deployment.PublicDirectories {
		result.Mounts = append(result.Mounts, id)
	}
	sort.Strings(result.Mounts)
	if d.Pending != nil {
		candidate := d.Pending.Candidate
		result.Candidate = &candidate
		result.Deadline = d.Pending.Deadline
		result.CandidateOrigin = m.candidateOrigin(candidate)
	}
	return result, nil
}

func (m *Manager) commit(ctx context.Context, j control.Journal, d Document, plan Plan) error {
	body, err := d.Encode(m.deployment)
	if err != nil {
		return err
	}
	next := j.Applied
	next.Number++
	next.Settings = body
	next.Gateway = plan.Gateway
	next.VPN = plan.VPN
	next.GatewaySettings = plan.Fingerprint
	return m.coordinator.Apply(ctx, j.Applied.Number, next)
}

// Propose 提交新旧入口并存的临时修订，确认期限固定五分钟。
func (m *Manager) Propose(ctx context.Context, expected uint64, candidate Site) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, d, err := m.load(ctx)
	if err != nil {
		return err
	}
	if j.Applied.Number != expected {
		return control.ErrRevisionConflict
	}
	if d.Pending != nil {
		return ErrFrozen
	}
	if reflect.DeepEqual(d.Site, candidate) {
		return &ValidationError{Cause: errors.New("设置没有变化")}
	}
	if err = (Document{Version: 1, Site: candidate}).Validate(m.deployment); err != nil {
		return &ValidationError{Cause: err}
	}
	// 入口确认时先更新网关再更新VPN，禁止新VPN抢占仍用于回滚的旧后台端口。
	if candidate.VPNPort == d.Site.AdminPort {
		return &ValidationError{Cause: errors.New("VPN端口不能直接复用旧后台端口，请分两次调整")}
	}
	plan, err := m.planner.Dual(ctx, d.Site, candidate, j.Applied)
	if err != nil {
		return err
	}
	// 在候选入口确认前，VPN必须继续使用已提交的旧身份和证书。
	if plan.VPN != j.Applied.VPN {
		return errors.New("临时入口计划不得提前改变VPN")
	}
	d.Pending = &Transition{Candidate: candidate, Deadline: m.now().Add(5 * time.Minute).Unix(), PreviousGateway: j.Applied.Gateway, PreviousVPN: j.Applied.VPN, PreviousFingerprint: j.Applied.GatewaySettings}
	return m.commit(ctx, j, d, plan)
}

func (m *Manager) candidateOrigin(site Site) string {
	if site.Domain == "" {
		return "http://127.0.0.1:" + strconv.Itoa(m.deployment.ControlPort)
	}
	return "https://" + net.JoinHostPort(site.Domain, strconv.Itoa(site.AdminPort))
}

// Confirm 由HTTP层先执行近期MFA，再在此核对新入口来源、期限及证书就绪。
func (m *Manager) Confirm(ctx context.Context, expected uint64, origin string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, d, err := m.load(ctx)
	if err != nil {
		return err
	}
	if j.Applied.Number != expected {
		return control.ErrRevisionConflict
	}
	if d.Pending == nil || m.now().Unix() >= d.Pending.Deadline || origin != m.candidateOrigin(d.Pending.Candidate) {
		return ErrConfirmation
	}
	if err = m.planner.Ready(ctx, d.Pending.Candidate); err != nil {
		return ErrConfirmation
	}
	plan, err := m.planner.Steady(ctx, d.Pending.Candidate, j.Applied)
	if err != nil {
		return err
	}
	remaining := time.Unix(d.Pending.Deadline, 0).Sub(m.now())
	if remaining <= 0 {
		return ErrConfirmation
	}
	bounded, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	d.Site = d.Pending.Candidate
	d.Pending = nil
	return m.commit(bounded, j, d, plan)
}

func (m *Manager) cancel(ctx context.Context, j control.Journal, d Document) error {
	if d.Pending == nil {
		return nil
	}
	old := d.Pending
	d.Pending = nil
	// 等待期间允许旧身份的证书自动续期；撤回入口不能恢复成已过期的旧VPN证书。
	return m.commit(ctx, j, d, Plan{Gateway: old.PreviousGateway, VPN: j.Applied.VPN, Fingerprint: old.PreviousFingerprint})
}

// Cancel 在旧入口或SSH管理通道撤回，失败由协调器保留临时修订以便重试。
func (m *Manager) Cancel(ctx context.Context, expected uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, d, err := m.load(ctx)
	if err != nil {
		return err
	}
	if j.Applied.Number != expected {
		return control.ErrRevisionConflict
	}
	return m.cancel(ctx, j, d)
}

// Reconcile 先恢复中断的组件事务，再处理已过期的临时入口；重启不会延长期限。
func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.coordinator.Recover(ctx); err != nil {
		return err
	}
	j, d, err := m.load(ctx)
	if err != nil {
		return err
	}
	if d.Pending != nil && m.now().Unix() >= d.Pending.Deadline {
		return m.cancel(ctx, j, d)
	}
	return nil
}

// RequireStable 是其他业务写入的前置门槛，调用后仍需使用同一修订号提交防止竞争。
func RequireStable(ctx context.Context, store control.Store, deployment config.Config) error {
	j, err := store.Load(ctx)
	if err != nil {
		return err
	}
	if j.Pending != nil {
		return ErrPending
	}
	if j.Applied.Settings == "" {
		return nil
	}
	d, err := Decode(j.Applied.Settings, deployment)
	if err != nil {
		return err
	}
	if d.Pending != nil {
		return ErrFrozen
	}
	return nil
}

// Package vpnservice 协调单用户VPN、证书版本与完整配置修订。
package vpnservice

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpnrunner"
)

// Runner 的状态不含原始配置；重启恢复由协调服务负责。
type Runner interface {
	Status(context.Context) (vpnrunner.State, error)
	Apply(context.Context, vpn.Desired) error
}

// Options 的路径与来源来自部署，不允许Web选择任意文件或解析器。
type Options struct {
	Settings           vpn.Settings
	Key                []byte
	PublishedDirectory string
	Source             func() (certificates.Pair, error)
	ReadPublished      func(vpn.Desired) (certificates.Pair, error)
}

// Status 是普通读取接口，口令、私钥、路径、密文均不在响应中。
type Status struct {
	Revision         uint64                 `json:"revision"`
	Enabled          bool                   `json:"enabled"`
	Running          bool                   `json:"running"`
	Pending          bool                   `json:"pending"`
	Domain           string                 `json:"domain"`
	Port             int                    `json:"port"`
	Certificate      *certificates.Metadata `json:"certificate,omitempty"`
	CertificateReady bool                   `json:"certificate_ready"`
	Message          string                 `json:"message"`
	Capabilities     vpn.Capabilities       `json:"capabilities"`
}

// Service 与反代共用协调器；业务锁只保护VPN自身，不使反代依赖VPN健康。
type Service struct {
	mu          sync.Mutex
	store       control.Store
	coordinator *control.Coordinator
	runner      Runner
	options     Options
}

// NewService 不主动启动VPN，未启用状态不依赖证书或公网域名。
func NewService(store control.Store, coordinator *control.Coordinator, runner Runner, options Options) *Service {
	options.Key = append([]byte(nil), options.Key...)
	return &Service{store: store, coordinator: coordinator, runner: runner, options: options}
}

func (s *Service) readPublished(d vpn.Desired) (certificates.Pair, error) {
	if s.options.ReadPublished != nil {
		pair, err := s.options.ReadPublished(d)
		if err == nil {
			err = s.validateMetadata(pair)
		}
		return pair, err
	}
	if !d.Enabled {
		return certificates.Pair{}, errors.New("VPN未启用")
	}
	// Compile先校验证书版本是64位散列，不能把数据库损坏转换成任意路径读取。
	if _, err := vpn.CompileTrojan(s.options.Settings, d); err != nil {
		return certificates.Pair{}, err
	}
	root := filepath.Join(s.options.PublishedDirectory, d.CertificateVersion)
	return certificates.ReadPairFiles(filepath.Join(root, "fullchain.pem"), filepath.Join(root, "private.key"), s.options.Settings.Domain, time.Now(), nil)
}

func (s *Service) validateMetadata(pair certificates.Pair) error {
	info := pair.Metadata()
	now := time.Now()
	if info.Domain != s.options.Settings.Domain || now.Before(info.NotBefore) || !now.Before(info.NotAfter) {
		return errors.New("证书域名或有效期不符合VPN部署")
	}
	return nil
}

// CertificateValid 给运行组件使用；无效或过期证书必须安全停止而不降级明文。
func (s *Service) CertificateValid(d vpn.Desired) error { _, err := s.readPublished(d); return err }

// Status 即使执行器暂时失联仍返回已提交意图，并明确实际状态未就绪。
func (s *Service) Status(ctx context.Context) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.store.Load(ctx)
	if err != nil {
		return Status{}, err
	}
	d, err := vpn.Open(s.options.Key, j.Applied.VPN)
	if err != nil {
		return Status{}, err
	}
	status := Status{Revision: j.Applied.Number, Enabled: d.Enabled, Pending: j.Pending != nil, Domain: s.options.Settings.Domain, Port: s.options.Settings.Port, Capabilities: vpn.TrojanCapabilities(), Message: "VPN未启用"}
	var pair certificates.Pair
	if d.Enabled {
		pair, err = s.readPublished(d)
	} else if s.options.Source != nil {
		pair, err = s.options.Source()
	} else {
		err = errors.New("证书来源未配置")
	}
	if err == nil {
		info := pair.Metadata()
		status.Certificate = &info
		status.CertificateReady = true
	}
	state, runnerErr := s.runner.Status(ctx)
	status.Running = runnerErr == nil && state.Running && state.Fingerprint == vpn.CommandFingerprint(d)
	if d.Enabled {
		switch {
		case !status.CertificateReady:
			status.Message = "证书无效或已过期，VPN暂停，等待有效证书"
		case runnerErr != nil:
			status.Message = "VPN执行器暂时不可达，等待恢复"
		case !status.Running:
			status.Message = "VPN进程未就绪，等待恢复"
		default:
			status.Message = "Trojan运行正常，启用TCP与UDP"
		}
	}
	return status, nil
}

// Apply 只允许启停或轮换随机口令，不接受原始密码、端口或文件路径。
func (s *Service) Apply(ctx context.Context, expected uint64, enabled, rotate bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.store.Load(ctx)
	if err != nil {
		return err
	}
	if j.Applied.Number != expected {
		return control.ErrRevisionConflict
	}
	d, err := vpn.Open(s.options.Key, j.Applied.VPN)
	if err != nil {
		return err
	}
	if enabled {
		if s.options.Source == nil {
			return errors.New("证书来源未配置")
		}
		pair, err := s.options.Source()
		if err != nil {
			return errors.New("尚无匹配且可信的有效证书")
		}
		if err = s.validateMetadata(pair); err != nil {
			return err
		}
		prepared, err := certificates.Prepare(s.options.PublishedDirectory, pair)
		if err != nil {
			return err
		}
		if !d.Enabled || rotate {
			d.Password, err = vpn.NewPassword()
			if err != nil {
				return err
			}
		}
		d.Enabled = true
		d.CertificateVersion = prepared.Version
	} else {
		d = vpn.Desired{}
	}
	if _, err = vpn.CompileTrojan(s.options.Settings, d); err != nil {
		return err
	}
	return s.commit(ctx, j, d)
}

func (s *Service) commit(ctx context.Context, j control.Journal, d vpn.Desired) error {
	value, err := vpn.Seal(s.options.Key, d)
	if err != nil {
		return err
	}
	next := j.Applied
	next.Number++
	next.VPN = value
	return s.coordinator.Apply(ctx, j.Applied.Number, next)
}

// Export 只导出正在运行且证书有效的已提交配置；HTTP层另行要求近期MFA。
func (s *Service) Export(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	if j.Pending != nil {
		return nil, errors.New("配置正在恢复，请稍后导出")
	}
	d, err := vpn.Open(s.options.Key, j.Applied.VPN)
	if err != nil {
		return nil, err
	}
	if _, err = s.readPublished(d); err != nil {
		return nil, errors.New("VPN证书未就绪")
	}
	state, err := s.runner.Status(ctx)
	if err != nil || !state.Running || state.Fingerprint != vpn.CommandFingerprint(d) {
		return nil, errors.New("VPN实际配置尚未就绪")
	}
	return vpn.ExportClash(s.options.Settings, d)
}

// Reconcile 恢复崩溃日志和执行器；证书有效时读取新版本，失败保留旧可信版本。
func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.coordinator.Recover(ctx); err != nil {
		return err
	}
	j, err := s.store.Load(ctx)
	if err != nil {
		return err
	}
	d, err := vpn.Open(s.options.Key, j.Applied.VPN)
	if err != nil {
		return err
	}
	if d.Enabled && s.options.Source != nil {
		if pair, sourceErr := s.options.Source(); sourceErr == nil && s.validateMetadata(pair) == nil {
			prepared, err := certificates.Prepare(s.options.PublishedDirectory, pair)
			if err != nil {
				return err
			}
			if prepared.Version != d.CertificateVersion {
				d.CertificateVersion = prepared.Version
				return s.commit(ctx, j, d)
			}
		}
	}
	effective := d
	if d.Enabled && s.CertificateValid(d) != nil {
		effective = vpn.Desired{}
	}
	state, err := s.runner.Status(ctx)
	if err != nil {
		return err
	}
	if state.Fingerprint != vpn.CommandFingerprint(effective) || state.Running != effective.Enabled {
		return s.runner.Apply(ctx, effective)
	}
	return nil
}

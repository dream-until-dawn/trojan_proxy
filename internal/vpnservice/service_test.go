package vpnservice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpnrunner"
)

type fakeRunner struct {
	state   vpnrunner.State
	applies int
	reject  bool
}

func TestCurrentProfileAndCoreWriteFreeze(t *testing.T) {
	ctx := context.Background()
	pair := pairFixture(t)
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "control.db"), control.Revision{Number: 1, Gateway: "unchanged"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	runner := &fakeRunner{}
	coordinator := control.NewCoordinator(db, untouchedGateway{}, vpnComponent{runner: runner, key: key})
	frozen := false
	service := NewService(db, coordinator, runner, Options{Settings: vpn.Settings{Domain: "vpn.example", Port: 18443}, Key: key, PublishedDirectory: filepath.Join(t.TempDir(), "published"), Source: func() (certificates.Pair, error) { return pair, nil }, ReadPublished: func(vpn.Desired) (certificates.Pair, error) { return pair, nil }, ProfileSource: func(context.Context) (*vpn.Profile, error) {
		return &vpn.Profile{Version: 1, Domain: "vpn.example", Port: 19443, AdminPort: 8007, OwnAddresses: []string{"198.51.100.10"}, Resolver: "9.9.9.9:53"}, nil
	}, WriteGuard: func(context.Context) error {
		if frozen {
			return errors.New("fixture entry pending")
		}
		return nil
	}})
	state, err := service.Status(ctx)
	if err != nil || state.Port != 19443 {
		t.Fatal("disabled status ignored current profile", state, err)
	}
	if err = service.Apply(ctx, 1, true, false); err != nil {
		t.Fatal(err)
	}
	j, err := db.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := vpn.Open(key, j.Applied.VPN)
	if err != nil || desired.Profile == nil || desired.Profile.Port != 19443 {
		t.Fatal("enable ignored current runtime profile", err)
	}
	frozen = true
	if err = service.Apply(ctx, j.Applied.Number, false, false); err == nil {
		t.Fatal("VPN service bypassed pending entry write freeze")
	}
	after, err := db.Load(ctx)
	if err != nil || after.Applied != j.Applied {
		t.Fatal("rejected VPN write changed revision", err)
	}
	state, err = service.Status(ctx)
	if err != nil || !state.Pending {
		t.Fatal("VPN pending settings not visible", state, err)
	}
}

func (r *fakeRunner) Status(context.Context) (vpnrunner.State, error) { return r.state, nil }
func (r *fakeRunner) Apply(_ context.Context, d vpn.Desired) error {
	r.applies++
	r.state = vpnrunner.State{Enabled: d.Enabled, Running: d.Enabled, Fingerprint: vpn.CommandFingerprint(d)}
	return nil
}

type vpnComponent struct {
	runner *fakeRunner
	key    []byte
}

func (c vpnComponent) Check(_ context.Context, value string) error {
	if c.runner.reject {
		return errors.New("固定引擎拒绝配置")
	}
	_, err := vpn.Open(c.key, value)
	return err
}
func (c vpnComponent) Apply(ctx context.Context, value string) error {
	d, err := vpn.Open(c.key, value)
	if err != nil {
		return err
	}
	return c.runner.Apply(ctx, d)
}

type untouchedGateway struct{}

func (untouchedGateway) Check(context.Context, string) error {
	return errors.New("VPN变更触碰了网关")
}
func (untouchedGateway) Apply(context.Context, string) error {
	return errors.New("VPN变更重载了网关")
}

func pairFixture(t *testing.T) certificates.Pair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), DNSNames: []string{"vpn.example"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := certificates.ValidatePair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), "vpn.example", now, roots)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func TestServiceRevisionExportRenewalAndSafePause(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	key := make([]byte, 32)
	store, err := storage.OpenJournal(ctx, filepath.Join(directory, "state.db"), control.Revision{Number: 1, Gateway: "gateway-stable", Rules: "[]"})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runner := &fakeRunner{}
	coordinator := control.NewCoordinator(store, untouchedGateway{}, vpnComponent{runner: runner, key: key})
	pair := pairFixture(t)
	published := filepath.Join(directory, "certificates")
	versions := map[string]certificates.Pair{}
	prepare := func(p certificates.Pair) {
		t.Helper()
		prepared, err := certificates.Prepare(published, p)
		if err != nil {
			t.Fatal(err)
		}
		versions[prepared.Version] = p
	}
	prepare(pair)
	sourceFailed, activeInvalid := false, false
	options := Options{Settings: vpn.Settings{Domain: "vpn.example", Port: 18443, OwnAddresses: []netip.Addr{netip.MustParseAddr("47.82.112.245")}, Resolver: netip.MustParseAddrPort("9.9.9.9:53")}, Key: key, PublishedDirectory: published,
		Source: func() (certificates.Pair, error) {
			if sourceFailed {
				return certificates.Pair{}, errors.New("签发服务暂时失败")
			}
			return pair, nil
		},
		ReadPublished: func(d vpn.Desired) (certificates.Pair, error) {
			if activeInvalid {
				return certificates.Pair{}, errors.New("证书到期")
			}
			p, ok := versions[d.CertificateVersion]
			if !d.Enabled || !ok {
				return certificates.Pair{}, errors.New("证书引用无效")
			}
			return p, nil
		}}
	service := NewService(store, coordinator, runner, options)
	if err = service.Apply(ctx, 1, true, false); err != nil {
		t.Fatal("启用失败", err)
	}
	j, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := vpn.Open(key, j.Applied.VPN)
	if err != nil || !first.Enabled || len(first.Password) != 43 {
		t.Fatal("未生成强随机凭据", err)
	}
	status, err := service.Status(ctx)
	if err != nil || !status.Running || status.Revision != 2 {
		t.Fatal("启用状态不一致", status, err)
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), first.Password) || strings.Contains(j.Applied.VPN, first.Password) {
		t.Fatal("状态或存储泄漏口令")
	}
	profile, err := service.Export(ctx)
	if err != nil || !strings.Contains(string(profile), first.Password) {
		t.Fatal("受控导出失败", err)
	}
	if err = service.Apply(ctx, 1, false, false); !errors.Is(err, control.ErrRevisionConflict) {
		t.Fatal("过时修订未拒绝", err)
	}
	sourceFailed = true
	applies := runner.applies
	if err = service.Reconcile(ctx); err != nil || runner.applies != applies {
		t.Fatal("签发失败打断了仍有效的VPN", err)
	}
	activeInvalid = true
	if err = service.Reconcile(ctx); err != nil || runner.state.Running {
		t.Fatal("证书失效未安全暂停", err)
	}
	if _, err = service.Export(ctx); err == nil {
		t.Fatal("证书失效仍导出")
	}
	status, err = service.Status(ctx)
	if err != nil || !status.Enabled || status.Running || status.CertificateReady {
		t.Fatal("安全暂停状态不清晰", status, err)
	}
	activeInvalid = false
	sourceFailed = false
	pair = pairFixture(t)
	prepare(pair)
	if err = service.Reconcile(ctx); err != nil {
		t.Fatal("新证书恢复失败", err)
	}
	j, err = store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := vpn.Open(key, j.Applied.VPN)
	if err != nil || second.Password != first.Password || second.CertificateVersion == first.CertificateVersion {
		t.Fatal("续期错误改变口令或未轮换版本", err)
	}
	if err = service.Apply(ctx, 3, true, true); err != nil {
		t.Fatal("口令轮换失败", err)
	}
	j, _ = store.Load(ctx)
	third, _ := vpn.Open(key, j.Applied.VPN)
	if third.Password == second.Password {
		t.Fatal("轮换未生成新口令")
	}
	if err = service.Apply(ctx, 4, false, false); err != nil {
		t.Fatal("停止失败", err)
	}
	if _, err = service.Export(ctx); err == nil {
		t.Fatal("停止后仍可导出")
	}
	j, _ = store.Load(ctx)
	if j.Applied.Gateway != "gateway-stable" || j.Applied.Rules != "[]" {
		t.Fatal("VPN操作修改了网关或规则")
	}
}

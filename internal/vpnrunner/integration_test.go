//go:build integration

package vpnrunner

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

// TestWriteExpiredFixture 用Go明确设置过去的有效期，避免依赖openssl负天数行为。
func TestWriteExpiredFixture(t *testing.T) {
	directory := "/certificates/" + strings.Repeat("a", 64)
	certificate, err := os.ReadFile(directory + "/fullchain.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificate)
	if block == nil {
		t.Fatal("夹具证书无效")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(directory + "/private.key")
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(key)
	if keyBlock == nil {
		t.Fatal("夹具私钥无效")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		t.Fatal("夹具私钥无法签名")
	}
	old := *leaf
	old.NotBefore = time.Now().Add(-2 * time.Hour)
	old.NotAfter = time.Now().Add(-time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &old, leaf, signer.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/certificates/"+strings.Repeat("d", 64)+"/fullchain.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0640); err != nil {
		t.Fatal(err)
	}
}

func TestRealRunnerLifecycle(t *testing.T) {
	ctx := context.Background()
	client := NewClient("/run/vpn/control.sock")
	desired := vpn.Desired{Enabled: true, Password: "fixture-only-password-0123456789abcdef", CertificateVersion: strings.Repeat("b", 64)}
	deadline := time.Now().Add(10 * time.Second)
	var state State
	var err error
	for {
		state, err = client.Status(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("受限Unix socket未就绪", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	phase := os.Getenv("TROJAN_RUNNER_PHASE")
	switch phase {
	case "first":
		if state.Enabled || state.Running {
			t.Fatal("初次启动不应自动启用VPN")
		}
		first := desired
		first.CertificateVersion = strings.Repeat("a", 64)
		if err = client.Check(ctx, first); err != nil {
			t.Fatal("真实引擎check失败", err)
		}
		state, err = client.Status(ctx)
		if err != nil || state.Running {
			t.Fatal("check改变运行状态", err)
		}
		if err = client.Apply(ctx, first); err != nil {
			t.Fatal("真实引擎启动失败", err)
		}
		if body, err := os.ReadFile("/run/vpn/private/config.json"); err == nil {
			t.Fatal("控制服务UID能够读取runner私有运行配置", len(body))
		}
		assertRunnerCertificate(t, first.CertificateVersion)
		if err = client.Apply(ctx, desired); err != nil {
			t.Fatal("证书轮换失败", err)
		}
		assertRunnerCertificate(t, desired.CertificateVersion)
		wrong := desired
		wrong.CertificateVersion = strings.Repeat("c", 64)
		if err = client.Apply(ctx, wrong); err == nil {
			t.Fatal("错误私钥未拒绝")
		}
		assertRunnerCertificate(t, desired.CertificateVersion)
		expired := desired
		expired.CertificateVersion = strings.Repeat("d", 64)
		if err = client.Check(ctx, expired); err != nil {
			t.Fatal("过期证书夹具未到达实际启动校验分支", err)
		}
		if err = client.Apply(ctx, expired); err == nil {
			t.Fatal("过期证书被激活")
		}
		assertRunnerCertificate(t, desired.CertificateVersion)
		state, err = client.Status(ctx)
		if err != nil || !state.Running || state.Fingerprint != vpn.CommandFingerprint(desired) {
			t.Fatal("启动失败未回退旧VPN", state, err)
		}
		key := make([]byte, 32)
		component := &Component{Key: key, Runner: client, CertificateValid: func(d vpn.Desired) error {
			if d.CertificateVersion == expired.CertificateVersion {
				return os.ErrInvalid
			}
			return nil
		}}
		sealed, err := vpn.Seal(key, expired)
		if err != nil {
			t.Fatal(err)
		}
		if err = component.Check(ctx, sealed); err == nil {
			t.Fatal("新修订允许激活已过期证书")
		}
		if err = component.Apply(ctx, sealed); err != nil {
			t.Fatal("旧修订恢复无法安全停用过期VPN", err)
		}
		state, err = client.Status(ctx)
		if err != nil || state.Running {
			t.Fatal("过期修订恢复未安全停用", state, err)
		}
		if err = client.Apply(ctx, desired); err != nil {
			t.Fatal("有效证书不能从安全暂停恢复", err)
		}
		assertRunnerCertificate(t, desired.CertificateVersion)
	case "crash":
		if !state.Enabled || state.Running {
			t.Fatal("引擎崩溃未反映实际状态", state)
		}
		if err = client.Apply(ctx, desired); err != nil {
			t.Fatal("同配置不能恢复已退出进程", err)
		}
		assertRunnerCertificate(t, desired.CertificateVersion)
	case "restart":
		if state.Enabled || state.Running {
			t.Fatal("runner重启后不应假称已有配置")
		}
		if err = client.Apply(ctx, desired); err != nil {
			t.Fatal("runner容器重启后恢复失败", err)
		}
		assertRunnerCertificate(t, desired.CertificateVersion)
	default:
		t.Fatal("未知探针阶段")
	}
}

func assertRunnerCertificate(t *testing.T, version string) {
	t.Helper()
	certificate, err := os.ReadFile("/certificates/" + version + "/fullchain.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificate)
	if block == nil {
		t.Fatal("夹具证书无效")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", "127.0.0.1:18443", &tls.Config{RootCAs: roots, ServerName: "probe.test", MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal("实际TLS握手不匹配发布版本", err)
	}
	conn.Close()
}

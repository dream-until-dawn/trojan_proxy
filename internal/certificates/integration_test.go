//go:build integration

package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCaddyManagedCacheAndPublish(t *testing.T) {
	ca, err := os.ReadFile("/cache/caddy/pki/authorities/local/root.crt")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("测试根无效")
	}
	pair, err := ReadManaged("/cache/caddy/certificates", "probe.test", time.Now(), roots)
	if err != nil {
		t.Fatal("固定版本Caddy缓存适配失败", err)
	}
	if pair.Metadata().Domain != "probe.test" {
		t.Fatal("证书域名元数据错误")
	}
	prepared, err := Prepare("/published", pair)
	if err != nil {
		t.Fatal("非root证书发布失败", err)
	}
	if os.Getenv("TROJAN_CERT_PHASE") == "first" {
		body, err := json.Marshal(prepared)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile("/published/first-version.json", body, 0640); err != nil {
			t.Fatal(err)
		}
	} else {
		body, err := os.ReadFile("/published/first-version.json")
		if err != nil {
			t.Fatal(err)
		}
		var previous Prepared
		if err = json.Unmarshal(body, &previous); err != nil {
			t.Fatal(err)
		}
		if previous.Version == prepared.Version || !prepared.Info.NotAfter.After(previous.Info.NotAfter) {
			t.Fatal("续期没有形成新的有效版本")
		}
		oldCert, err := os.ReadFile(filepath.Join("/published", previous.Version, "fullchain.pem"))
		if err != nil {
			t.Fatal(err)
		}
		oldKey, err := os.ReadFile(filepath.Join("/published", previous.Version, "private.key"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tls.X509KeyPair(oldCert, oldKey); err != nil {
			t.Fatal("发布新版本破坏旧证书对", err)
		}
	}
	if _, err = ReadManaged("/cache/caddy/certificates", "other.test", time.Now(), roots); err == nil {
		t.Fatal("跨域读取被接受")
	}
	key, err := os.ReadFile(prepared.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := os.ReadFile(prepared.CertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tls.X509KeyPair(cert, key); err != nil {
		t.Fatal("发布后证书对损坏", err)
	}
	if _, err = ReadManaged("/cache/caddy/certificates", "probe.test", time.Now(), x509.NewCertPool()); err == nil {
		t.Fatal("错误信任根通过")
	}
}

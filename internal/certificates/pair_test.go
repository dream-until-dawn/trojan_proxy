package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, notBefore, notAfter time.Time) ([]byte, []byte, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe CA"}, NotBefore: notBefore.Add(-24 * time.Hour), NotAfter: notAfter.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	caParsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "probe.test"}, DNSNames: []string{"probe.test"}, NotBefore: notBefore, NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caParsed, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	private := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	roots := x509.NewCertPool()
	roots.AddCert(caParsed)
	return cert, private, roots
}

func TestPairValidationAndImmutablePublish(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cert, key, roots := fixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	pair, err := ValidatePair(cert, key, "probe.test", now, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ValidatePair(cert, key, "wrong.test", now, roots); err == nil {
		t.Fatal("错误域名通过")
	}
	if _, err = ValidatePair(cert, key, "probe.test", now, x509.NewCertPool()); err == nil {
		t.Fatal("错误信任根通过")
	}
	if _, err = ValidatePair(cert, key, "probe.test", now.Add(2*time.Hour), roots); err == nil {
		t.Fatal("过期证书通过")
	}
	if _, err = ValidatePair(cert, key, "probe.test", now.Add(-2*time.Hour), roots); err == nil {
		t.Fatal("尚未生效证书通过")
	}
	_, wrongKey, _ := fixture(t, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err = ValidatePair(cert, wrongKey, "probe.test", now, roots); err == nil {
		t.Fatal("错误私钥通过")
	}
	encoded, err := json.Marshal(pair)
	if err != nil || strings.Contains(string(encoded), "PRIVATE") {
		t.Fatal("Pair泄漏秘密", err)
	}
	directory := filepath.Join(t.TempDir(), "published")
	prepared, err := Prepare(directory, pair)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Prepare(directory, pair)
	if err != nil || second.Version != prepared.Version {
		t.Fatal("同版本不能幂等复用", err)
	}
	if _, err = Prepare(directory, Pair{}); err == nil {
		t.Fatal("未经校验材料被发布")
	}
	actual, err := os.ReadFile(prepared.KeyPath)
	if err != nil || string(actual) != string(key) {
		t.Fatal("拒绝操作改变已有版本", err)
	}
	_, err = Prepare(directory, Pair{})
	if err == nil {
		t.Fatal("空材料发布通过")
	}
}

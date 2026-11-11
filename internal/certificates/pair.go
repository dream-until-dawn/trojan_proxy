// Package certificates 校验证书身份、信任与密钥配对，不输出私钥。
package certificates

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Metadata 适合管理界面展示，不包含主机路径和秘密。
type Metadata struct {
	Domain      string    `json:"domain"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint"`
}

// Pair 是已校验的一对PEM；禁止通过JSON意外导出密钥。
type Pair struct {
	info        Metadata
	certificate []byte
	key         []byte
}

// Metadata 返回只读元数据副本；密钥材料不对包外暴露。
func (p Pair) Metadata() Metadata { return p.info }

// ValidatePair 默认使用系统信任根；测试或明确授权的私有CA可传入roots。
func ValidatePair(certificate, key []byte, domain string, now time.Time, roots *x509.CertPool) (Pair, error) {
	if len(certificate) > 1024*1024 || len(key) > 65536 || domain == "" {
		return Pair{}, errors.New("证书材料过大或域名为空")
	}
	paired, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return Pair{}, errors.New("证书和私钥无法配对")
	}
	if len(paired.Certificate) == 0 {
		return Pair{}, errors.New("证书链为空")
	}
	leaf, err := x509.ParseCertificate(paired.Certificate[0])
	if err != nil {
		return Pair{}, errors.New("叶证书格式无效")
	}
	switch public := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if public.N.BitLen() < 2048 {
			return Pair{}, errors.New("RSA密钥不足2048位")
		}
	case *ecdsa.PublicKey:
		if public.Curve.Params().BitSize < 256 {
			return Pair{}, errors.New("椭圆曲线密钥不足256位")
		}
	case ed25519.PublicKey:
	default:
		return Pair{}, errors.New("不支持的证书密钥类型")
	}
	intermediates := x509.NewCertPool()
	for _, der := range paired.Certificate[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return Pair{}, errors.New("证书链格式无效")
		}
		intermediates.AddCert(cert)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: domain, CurrentTime: now, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return Pair{}, fmt.Errorf("证书身份验证失败: %w", err)
	}
	digest := sha256.Sum256(leaf.Raw)
	return Pair{info: Metadata{Domain: domain, Issuer: leaf.Issuer.String(), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Fingerprint: hex.EncodeToString(digest[:])}, certificate: append([]byte(nil), certificate...), key: append([]byte(nil), key...)}, nil
}

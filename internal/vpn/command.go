package vpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

// commandWire 仅用于加密前和权限受限的Unix传输，不能作为普通状态响应。
type commandWire struct {
	Enabled            bool     `json:"enabled"`
	Password           string   `json:"password"`
	CertificateVersion string   `json:"certificate_version"`
	Profile            *Profile `json:"profile,omitempty"`
}

// EncodeCommand 返回含秘密的命令，只能交给加密器或受限runner，不得打印日志。
func EncodeCommand(d Desired) ([]byte, error) {
	return json.Marshal(commandWire{Enabled: d.Enabled, Password: d.Password, CertificateVersion: d.CertificateVersion, Profile: d.Profile})
}

// DecodeCommand 严格限制执行器的输入，不接受原生引擎JSON和额外字段。
func DecodeCommand(body []byte) (Desired, error) {
	if len(body) > 4096 {
		return Desired{}, errors.New("VPN命令超出限制")
	}
	var wire commandWire
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Desired{}, errors.New("VPN命令格式错误")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Desired{}, errors.New("VPN命令必须只有一个对象")
	}
	if !wire.Enabled && (wire.Password != "" || wire.CertificateVersion != "" || wire.Profile != nil) {
		return Desired{}, errors.New("停止命令不得携带秘密或证书")
	}
	return Desired{Enabled: wire.Enabled, Password: wire.Password, CertificateVersion: wire.CertificateVersion, Profile: wire.Profile}, nil
}

// CommandFingerprint 只用于确认运行态与目标一致，不包含原始秘密。
func CommandFingerprint(d Desired) string {
	body, _ := EncodeCommand(d)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("VPN主密钥必须为32字节")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Seal 使用独立AAD加密配置，不能与TOTP密文互换。
func Seal(key []byte, d Desired) (string, error) {
	plain, err := EncodeCommand(d)
	if err != nil {
		return "", err
	}
	gcm, err := aead(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, plain, []byte("trojan-vpn-command-v1"))), nil
}

// Open 验证密文再解析；空配置表示尚未启用，重放防护由修订协调器负责。
func Open(key []byte, value string) (Desired, error) {
	if value == "" {
		return Desired{}, nil
	}
	if len(value) > 8192 {
		return Desired{}, errors.New("VPN密文超出限制")
	}
	gcm, err := aead(key)
	if err != nil {
		return Desired{}, err
	}
	encrypted, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(encrypted) < gcm.NonceSize() {
		return Desired{}, errors.New("VPN密文格式错误")
	}
	plain, err := gcm.Open(nil, encrypted[:gcm.NonceSize()], encrypted[gcm.NonceSize():], []byte("trojan-vpn-command-v1"))
	if err != nil {
		return Desired{}, errors.New("VPN密文校验失败")
	}
	return DecodeCommand(plain)
}

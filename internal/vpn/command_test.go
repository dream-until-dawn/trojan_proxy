package vpn

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
)

func TestEncryptedCommandIsolation(t *testing.T) {
	_, d := fixture()
	key := make([]byte, 32)
	one, err := Seal(key, d)
	if err != nil {
		t.Fatal(err)
	}
	two, err := Seal(key, d)
	if err != nil || one == two || strings.Contains(one, d.Password) {
		t.Fatal("密文未使用随机nonce或泄漏密码", err)
	}
	opened, err := Open(key, one)
	if err != nil || opened != d {
		t.Fatal("VPN密文不能还原", err)
	}
	other := make([]byte, 32)
	other[0] = 1
	if _, err = Open(other, one); err == nil {
		t.Fatal("错误主密钥被接受")
	}
	if _, err = Open(key, one[:len(one)-2]+"xx"); err == nil {
		t.Fatal("篡改密文被接受")
	}
	secret, err := auth.EncryptSecret(key, "totp-fixture")
	if err != nil {
		t.Fatal(err)
	}
	// 独立AAD必须拒绝其他用途的完整、未篡改密文。
	if _, err = Open(key, base64.RawStdEncoding.EncodeToString(secret)); err == nil {
		t.Fatal("TOTP密文被当作VPN命令")
	}
	for _, body := range []string{`{"enabled":true,"command":"sh"}`, `{"enabled":false,"password":"secret"}`, `{} {}`} {
		if _, err = DecodeCommand([]byte(body)); err == nil {
			t.Fatal("非法执行器命令未拒绝", body)
		}
	}
}

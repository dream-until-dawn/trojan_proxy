package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestPassword(t *testing.T) {
	password := "probe-only-long-random-password"
	a, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("随机盐未生效")
	}
	if !VerifyPassword(a, password) {
		t.Fatal("正确口令拒绝")
	}
	if VerifyPassword(a, "wrong-password") {
		t.Fatal("错误口令通过")
	}
	if VerifyPassword(strings.Replace(a, "m=65536", "m=4294967295", 1), password) {
		t.Fatal("恶意内存参数通过")
	}
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("过短口令通过")
	}
}

func TestTOTPRFCVectorsAndReplay(t *testing.T) {
	// RFC6238 SHA1测试密钥；原始8位向量取低6位以匹配本产品默认位数。
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, v := range []struct {
		unix     int64
		expected string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		step, ok := VerifyTOTP(secret, v.expected, time.Unix(v.unix, 0), -1)
		if !ok || step != v.unix/30 {
			t.Fatalf("标准向量失败: %d", v.unix)
		}
		if _, ok = VerifyTOTP(secret, v.expected, time.Unix(v.unix, 0), step); ok {
			t.Fatal("同一步长重放通过")
		}
	}
	if _, ok := VerifyTOTP(secret, "287082", time.Unix(150, 0), -1); ok {
		t.Fatal("过期验证码通过")
	}
	for _, bad := range []string{"", "12345", "1234567", "12a456"} {
		if _, ok := VerifyTOTP(secret, bad, time.Unix(59, 0), -1); ok {
			t.Fatal("非法验证码通过")
		}
	}
	if _, ok := VerifyTOTP("bad secret", "123456", time.Unix(59, 0), -1); ok {
		t.Fatal("非法秘密通过")
	}
}

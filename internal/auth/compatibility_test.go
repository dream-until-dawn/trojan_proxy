package auth

import "testing"

// 固定假口令散列由x/crypto v0.48.0生成，不能用新版本自己生成再验证来代替兼容性测试。
func TestLegacyArgon2PasswordCompatibility(t *testing.T) {
	const legacy = "$argon2id$v=19$m=65536,t=3,p=1$NoQ/z5ircVL8EhRy2qModw$3QICtwRgjkzg2lWh9+h/gkYjDceeQTbs8RXkb3G/ODM"
	if !VerifyPassword(legacy, "legacy-fixture-password-2026") {
		t.Fatal("依赖升级导致已有管理员散列不兼容")
	}
	if VerifyPassword(legacy, "wrong-fixture-password-2026") {
		t.Fatal("旧散列接受了错误口令")
	}
}

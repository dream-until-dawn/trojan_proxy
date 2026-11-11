package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"time"
)

// NewTOTPSecret 生成兼容标准验证器的160位秘密，调用方必须加密保存。
func NewTOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), nil
}

func code(secret []byte, counter int64) string {
	var block [8]byte
	binary.BigEndian.PutUint64(block[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	mac.Write(block[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

// VerifyTOTP 接受当前30秒步长及前后一档，拒绝已消费步长。
// 调用方必须在同一个持久化事务内校验并更新 lastCounter，防止并发重放。
func VerifyTOTP(secret, input string, now time.Time, lastCounter int64) (int64, bool) {
	if len(input) != 6 || len(secret) != 32 {
		return 0, false
	}
	for _, digit := range input {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) < 20 {
		return 0, false
	}
	step := now.Unix() / 30
	for _, delta := range []int64{0, -1, 1} {
		counter := step + delta
		if counter < 0 || counter <= lastCounter {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(code(key, counter)), []byte(input)) == 1 {
			return counter, true
		}
	}
	return 0, false
}

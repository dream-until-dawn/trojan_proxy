// authprobe 只测量虚构口令的 Argon2id 成本，不读取真实凭据。
package main

import (
	"encoding/json"
	"golang.org/x/crypto/argon2"
	"os"
	"time"
)

func main() {
	const memoryKiB = 64 * 1024
	var times []int64
	for i := 0; i < 5; i++ {
		start := time.Now()
		key := argon2.IDKey([]byte("probe-only-not-a-real-password"), []byte("probe-only-salt!"), 3, memoryKiB, 1, 32)
		if len(key) != 32 {
			panic("散列长度错误")
		}
		times = append(times, time.Since(start).Milliseconds())
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"memory_kib": memoryKiB, "iterations": 3, "parallelism": 1, "durations_ms": times, "scope": "仅散列成本；不是认证安全验收"})
}

//go:build !linux

package files

// 非 Linux 仅用于开发测试；生产验收平台为 Linux。
const nonblockFlag = 0

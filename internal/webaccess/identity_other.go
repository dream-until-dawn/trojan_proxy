//go:build !linux && !windows

package webaccess

import (
	"errors"
	"os"
)

func fileIdentity(*os.File) (string, error) {
	return "", errors.New("访问采集仅支持Linux生产部署")
}

//go:build !linux

package deployment

import (
	"context"
	"errors"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
)

func Prepare(context.Context, config.Config, Paths) error {
	return errors.New("默认部署初始化仅支持Linux Docker")
}

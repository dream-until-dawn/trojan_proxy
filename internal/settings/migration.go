package settings

import (
	"context"
	"errors"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

// ErrPending 表示应先完成既有修订，不能把准备中的配置当成未初始化。
var ErrPending = errors.New("请先恢复未完成修订，再迁移业务设置")

// EnsureImported 只在完整修订尚无业务设置时导入；保留网关、VPN和规则的原始快照。
// 迁移同样经过协调器，避免另一进程或其他业务写入被启动阶段覆盖。
func EnsureImported(ctx context.Context, store control.Store, coordinator *control.Coordinator, legacy config.Config) (Document, error) {
	for range 3 {
		journal, err := store.Load(ctx)
		if err != nil {
			return Document{}, err
		}
		if journal.Pending != nil {
			return Document{}, ErrPending
		}
		if journal.Applied.Settings != "" {
			return Decode(journal.Applied.Settings, legacy)
		}
		document := FromLegacy(legacy)
		body, err := document.Encode(legacy)
		if err != nil {
			return Document{}, err
		}
		next := journal.Applied
		next.Number++
		next.Settings = body
		err = coordinator.Apply(ctx, journal.Applied.Number, next)
		if errors.Is(err, control.ErrRevisionConflict) {
			continue
		}
		return document, err
	}
	return Document{}, control.ErrRevisionConflict
}

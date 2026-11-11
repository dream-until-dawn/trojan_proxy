// Package runtime 协调配置应用与崩溃恢复，不假设跨进程原子提交。
package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ErrRevisionConflict 表示客户端基于过时快照提交，应刷新后重新确认。
var ErrRevisionConflict = errors.New("修订号冲突")

// Revision 是一次完整配置快照；编号由持久化存储层分配。
type Revision struct {
	Number  uint64 `json:"number"`
	Gateway string `json:"gateway"`
	VPN     string `json:"vpn"`
	Rules   string `json:"rules,omitempty"`
}

// Journal 保留旧快照直到两个组件都应用成功。
type Journal struct {
	Applied Revision  `json:"applied"`
	Pending *Revision `json:"pending,omitempty"`
}

// Store 必须保证 Save 的崩溃一致性；SQLite 实现需要事务提交。
type Store interface {
	Load(context.Context) (Journal, error)
	Save(context.Context, Journal) error
}

// Component 是受限引擎适配器，Check 不得改变运行态，Apply 必须可重试。
type Component interface {
	Check(context.Context, string) error
	Apply(context.Context, string) error
}

// Coordinator 串行化应用操作；启动必须先 Recover 再开放写入接口。
type Coordinator struct {
	mu      sync.Mutex
	store   Store
	gateway Component
	vpn     Component
}

// NewCoordinator 连接存储与组件；不会自动修改运行态。
func NewCoordinator(store Store, gateway, vpn Component) *Coordinator {
	return &Coordinator{store: store, gateway: gateway, vpn: vpn}
}

// Recover 将未完成的修订恢复为最后已提交快照；任何失败保留 pending。
func (c *Coordinator) Recover(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	j, err := c.store.Load(ctx)
	if err != nil {
		return err
	}
	if j.Pending == nil {
		return nil
	}
	return c.rollback(ctx, j)
}

func (c *Coordinator) rollback(ctx context.Context, j Journal) error {
	// 即使第一个组件失败也尝试恢复另一个，避免不必要的扩大故障。
	var gatewayErr, vpnErr error
	if j.Pending != nil && j.Pending.Gateway != j.Applied.Gateway {
		gatewayErr = c.gateway.Apply(ctx, j.Applied.Gateway)
	}
	if j.Pending != nil && j.Pending.VPN != j.Applied.VPN {
		vpnErr = c.vpn.Apply(ctx, j.Applied.VPN)
	}
	err := errors.Join(gatewayErr, vpnErr)
	if err != nil {
		return fmt.Errorf("回滚未完成，保留待恢复修订: %w", err)
	}
	j.Pending = nil
	return c.store.Save(ctx, j)
}

// Apply 使用 expected 防止覆盖并发修改；失败后尽力回滚并返回原始原因。
func (c *Coordinator) Apply(ctx context.Context, expected uint64, next Revision) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	j, err := c.store.Load(ctx)
	if err != nil {
		return err
	}
	if j.Pending != nil {
		return errors.New("存在未完成修订，请先恢复")
	}
	if j.Applied.Number != expected || next.Number != expected+1 {
		return ErrRevisionConflict
	}
	if next.Gateway != j.Applied.Gateway {
		if err = c.gateway.Check(ctx, next.Gateway); err != nil {
			return err
		}
	}
	if next.VPN != j.Applied.VPN {
		if err = c.vpn.Check(ctx, next.VPN); err != nil {
			return err
		}
	}
	j.Pending = &next
	if err = c.store.Save(ctx, j); err != nil {
		return err
	}
	if next.Gateway != j.Applied.Gateway {
		err = c.gateway.Apply(ctx, next.Gateway)
	}
	if err == nil && next.VPN != j.Applied.VPN {
		err = c.vpn.Apply(ctx, next.VPN)
	}
	if err == nil {
		err = c.store.Save(ctx, Journal{Applied: next})
	}
	if err == nil {
		return nil
	}
	// 请求取消不能阻断恢复；清理时间单独限制，避免无限等待。
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), recoveryTimeout)
	defer cancel()
	return errors.Join(err, c.rollback(recoveryCtx, j))
}

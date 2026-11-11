package routing

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

func TestPersistentSettingsAndPendingEntrySurviveReconcile(t *testing.T) {
	ctx := context.Background()
	fallback := gateway.Settings{Domain: "example.com", AdminPort: 8007, ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443}}
	db := &store{journal: control.Journal{Applied: control.Revision{Number: 1}}}
	g := &engine{value: `{"apps":{}}`}
	provider := func(_ context.Context, revision control.Revision) (gateway.Settings, bool, error) {
		next := fallback
		if revision.Settings == "corrupt" {
			return next, false, errors.New("fixture invalid persisted settings")
		}
		if revision.Settings == "new" {
			next.AdminPort = 8006
			next.Policy.AdminPort = 8006
		}
		return next, revision.Settings == "pending", nil
	}
	s := NewServiceWithProvider(db, g, fallback, control.NewCoordinator(db, g, unchangedVPN{}), provider)
	if _, err := s.List(ctx); err != nil {
		t.Fatal(err)
	}
	// 模拟设置协调器已经提交新参数；存活的路由服务不能继续使用启动文件中的端口。
	db.journal.Applied.Number++
	db.journal.Applied.Settings = "new"
	if err := s.Reconcile(ctx); err != nil || !strings.Contains(g.value, `":8006"`) || strings.Contains(g.value, `":8007"`) {
		t.Fatal("reconcile overwrote persisted settings", g.value, err)
	}
	// 临时入口的快照必须原样保留，即使它的指纹不等于稳态参数的指纹。
	db.journal.Applied.Number++
	db.journal.Applied.Settings = "pending"
	db.journal.Applied.Gateway = `{"dual-entry":true}`
	db.journal.Applied.GatewaySettings = "pending-fingerprint"
	pendingNumber := db.journal.Applied.Number
	if err := s.Reconcile(ctx); err != nil || g.value != `{"dual-entry":true}` || db.journal.Applied.Number != pendingNumber {
		t.Fatal("reconcile destroyed pending dual entry", g.value, err)
	}
	number := db.journal.Applied.Number
	if err := s.Apply(ctx, number, nil); !errors.Is(err, ErrWriteFrozen) {
		t.Fatal("route service bypassed pending entry write freeze", err)
	}
	if db.journal.Applied.Number != number || g.value != `{"dual-entry":true}` {
		t.Fatal("frozen write altered pending snapshot")
	}
	// 新进程也必须识别待确认状态，不能依赖旧进程内存。
	restarted := NewServiceWithProvider(db, g, fallback, control.NewCoordinator(db, g, unchangedVPN{}), provider)
	if _, err := restarted.List(ctx); err != nil || g.value != `{"dual-entry":true}` {
		t.Fatal("restart destroyed pending dual entry", err)
	}
	db.journal.Applied.Settings = "corrupt"
	if err := restarted.Reconcile(ctx); err == nil || g.value != `{"dual-entry":true}` {
		t.Fatal("corrupt settings fell back to deployment file", err)
	}
}

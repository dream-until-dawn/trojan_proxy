package routing

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

type store struct{ journal control.Journal }

func (s *store) Load(context.Context) (control.Journal, error)   { return s.journal, nil }
func (s *store) Save(_ context.Context, j control.Journal) error { s.journal = j; return nil }

type engine struct {
	value  string
	reject bool
}

func TestLegacySettingsMigrationAndFailureRollback(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rejected"}[reject], func(t *testing.T) {
			ctx := context.Background()
			ruleset := []routes.Rule{{ID: "app", Name: "服务", Port: 18001, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3000}}
			body, _ := json.Marshal(ruleset)
			old := control.Revision{Number: 7, Gateway: `{"apps":{}}`, VPN: "unchanged-encrypted-vpn", Rules: string(body)}
			db := &store{journal: control.Journal{Applied: old}}
			g := &engine{value: old.Gateway, reject: reject}
			settings := gateway.Settings{Domain: "qin-xin.top", AdminPort: 8007, ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443}}
			state, err := NewService(db, g, settings).List(ctx)
			if reject {
				if err == nil || db.journal.Applied != old || db.journal.Pending != nil || g.value != old.Gateway {
					t.Fatal("迁移失败未保留旧修订", err)
				}
				return
			}
			if err != nil || state.Revision != 8 || len(state.Rules) != 1 || db.journal.Applied.VPN != old.VPN || !strings.Contains(g.value, `"protocols":["h1","h2"]`) {
				t.Fatal("安全策略迁移未保持完整修订", state, err)
			}
			if _, err = NewService(db, g, settings).List(ctx); err != nil || db.journal.Applied.Number != 8 {
				t.Fatal("同设置重复迁移", err)
			}
			settings.AdminPort = 8006
			settings.Policy.AdminPort = 8006
			if _, err = NewService(db, g, settings).List(ctx); err != nil || db.journal.Applied.Number != 9 || !strings.Contains(g.value, `":8006"`) {
				t.Fatal("部署设置变化未形成新修订", err)
			}
		})
	}
}

func (e *engine) Current(context.Context) (string, error) { return e.value, nil }
func (e *engine) Check(context.Context, string) error     { return nil }
func (e *engine) Apply(_ context.Context, v string) error {
	if e.reject && v != `{"apps":{}}` {
		return errors.New("模拟端口冲突")
	}
	e.value = v
	return nil
}
func TestApplyRecoveryAndConflict(t *testing.T) {
	ctx := context.Background()
	db := &store{journal: control.Journal{Applied: control.Revision{Number: 1}}}
	g := &engine{value: `{"apps":{}}`}
	settings := gateway.Settings{Domain: "qin-xin.top", AdminPort: 8007, ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443}}
	s := NewService(db, g, settings)
	r := routes.Rule{ID: "app", Name: "应用", Port: 18001, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3000}
	g.reject = true
	if err := s.Apply(ctx, 1, []routes.Rule{r}); err == nil {
		t.Fatal("应用失败未报告")
	}
	if db.journal.Applied.Number != 1 || db.journal.Pending != nil || g.value != `{"apps":{}}` {
		t.Fatal("失败未回滚")
	}
	g.reject = false
	if err := s.Apply(ctx, 1, []routes.Rule{r}); err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(ctx, 1, nil); !errors.Is(err, control.ErrRevisionConflict) {
		t.Fatal("过时修订未拒绝", err)
	}
	committed := g.value
	g.value = `{"apps":{}}`
	restarted := NewService(db, g, settings)
	state, err := restarted.List(ctx)
	if err != nil || state.Revision != 2 || len(state.Rules) != 1 || g.value != committed {
		t.Fatal("重启未恢复业务配置", state, err)
	}
}

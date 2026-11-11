package routing

import (
	"context"
	"errors"
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

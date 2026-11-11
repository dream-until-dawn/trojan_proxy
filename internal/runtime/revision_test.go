package runtime

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type memoryStore struct {
	j        Journal
	failSave int
	saves    int
}

func (s *memoryStore) Load(context.Context) (Journal, error) { return s.j, nil }
func (s *memoryStore) Save(_ context.Context, j Journal) error {
	s.saves++
	if s.saves == s.failSave {
		return errors.New("模拟提交失败")
	}
	s.j = j
	return nil
}

type component struct {
	value  string
	reject string
	fail   string
}

func (c *component) Check(_ context.Context, value string) error {
	if value == c.reject {
		return errors.New("配置检查拒绝")
	}
	return nil
}
func (c *component) Apply(ctx context.Context, value string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if value == c.fail {
		return errors.New("组件应用失败")
	}
	c.value = value
	return nil
}
func fixture() (*memoryStore, *component, *component, *Coordinator) {
	s := &memoryStore{j: Journal{Applied: Revision{Number: 1, Gateway: "old-g", VPN: "old-v"}}}
	g, v := &component{value: "old-g"}, &component{value: "old-v"}
	return s, g, v, NewCoordinator(s, g, v)
}
func next() Revision { return Revision{Number: 2, Gateway: "new-g", VPN: "new-v"} }
func TestApplyCommit(t *testing.T) {
	s, g, v, c := fixture()
	if err := c.Apply(context.Background(), 1, next()); err != nil {
		t.Fatal(err)
	}
	if s.j.Applied.Number != 2 || s.j.Pending != nil || g.value != "new-g" || v.value != "new-v" {
		t.Fatal("修订未一致提交")
	}
}
func TestBadConfigDoesNotPrepare(t *testing.T) {
	s, g, _, c := fixture()
	g.reject = "new-g"
	if err := c.Apply(context.Background(), 1, next()); err == nil {
		t.Fatal("未拒绝非法配置")
	}
	if s.saves != 0 || g.value != "old-g" {
		t.Fatal("校验失败仍修改运行态")
	}
}
func TestApplyAndCommitFailureRollback(t *testing.T) {
	for _, mode := range []string{"vpn", "commit"} {
		t.Run(mode, func(t *testing.T) {
			s, g, v, c := fixture()
			if mode == "vpn" {
				v.fail = "new-v"
			} else {
				s.failSave = 2
			}
			if err := c.Apply(context.Background(), 1, next()); err == nil {
				t.Fatal("未报告应用失败")
			}
			if g.value != "old-g" || v.value != "old-v" || s.j.Pending != nil || s.j.Applied.Number != 1 {
				t.Fatal("失败后未恢复旧快照")
			}
		})
	}
}
func TestRecoverAfterEachCrashPoint(t *testing.T) {
	for _, stage := range []string{"prepared", "gateway", "vpn"} {
		t.Run(stage, func(t *testing.T) {
			s, g, v, _ := fixture()
			n := next()
			s.j.Pending = &n
			if stage != "prepared" {
				g.value = "new-g"
			}
			if stage == "vpn" {
				v.value = "new-v"
			}
			// 使用新协调器模拟进程重启，状态只能来自存储，不能依赖旧对象内存。
			c := NewCoordinator(s, g, v)
			if err := c.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if s.j.Pending != nil || g.value != "old-g" || v.value != "old-v" {
				t.Fatal("崩溃恢复不一致")
			}
		})
	}
}
func TestFailedRecoveryRetainsPending(t *testing.T) {
	s, g, v, c := fixture()
	n := next()
	s.j.Pending = &n
	g.fail = "old-g"
	v.value = "new-v"
	err := c.Recover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "回滚未完成") {
		t.Fatal("未报告恢复失败")
	}
	if s.j.Pending == nil || v.value != "old-v" {
		t.Fatal("恢复失败丢失日志或未尝试另一组件")
	}
	if err := c.Apply(context.Background(), 1, next()); err == nil {
		t.Fatal("恢复失败后仍接受新写入")
	}
}
func TestRevisionConflict(t *testing.T) {
	s, _, _, c := fixture()
	if err := c.Apply(context.Background(), 0, next()); err == nil {
		t.Fatal("未拒绝过时修订")
	}
	if s.saves != 0 {
		t.Fatal("冲突仍写入")
	}
}

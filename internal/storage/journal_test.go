package storage

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

func TestAbruptProcessExit(t *testing.T) {
	ctx := context.Background()
	if os.Getenv("TROJAN_JOURNAL_CRASH_CHILD") == "1" {
		s, err := OpenJournal(ctx, os.Getenv("TROJAN_JOURNAL_TEST_PATH"), control.Revision{Number: 1, Gateway: "old-g", VPN: "old-v"})
		if err != nil {
			t.Fatal(err)
		}
		next := control.Revision{Number: 2, Gateway: "new-g", VPN: "new-v"}
		if err = s.Save(ctx, control.Journal{Applied: control.Revision{Number: 1, Gateway: "old-g", VPN: "old-v"}, Pending: &next}); err != nil {
			t.Fatal(err)
		}
		// 直接退出，不关闭连接、不执行 defer，验证 WAL 的真实进程退出恢复。
		os.Exit(17)
	}
	path := filepath.Join(t.TempDir(), "crash.db")
	child := exec.Command(os.Args[0], "-test.run=^TestAbruptProcessExit$")
	child.Env = append(os.Environ(), "TROJAN_JOURNAL_CRASH_CHILD=1", "TROJAN_JOURNAL_TEST_PATH="+path)
	output, err := child.CombinedOutput()
	if exited, ok := err.(*exec.ExitError); !ok || exited.ExitCode() != 17 {
		t.Fatalf("子进程未到达指定崩溃点: %v %s", err, output)
	}
	s, err := OpenJournal(ctx, path, control.Revision{Number: 99})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	j, err := s.Load(ctx)
	if err != nil || j.Pending == nil || j.Pending.Number != 2 {
		t.Fatalf("崩溃丢失已提交日志: %+v %v", j, err)
	}
	g, v := &engine{value: "new-g"}, &engine{value: "new-v"}
	if err = control.NewCoordinator(s, g, v).Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if g.value != "old-g" || v.value != "old-v" {
		t.Fatal("进程异常退出后未恢复旧配置")
	}
}

func TestAuditCommitIsAtomicAndRedacted(t *testing.T) {
	ctx := context.Background()
	s, err := OpenJournal(ctx, filepath.Join(t.TempDir(), "audit.db"), control.Revision{Number: 1, Gateway: "secret-old"})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	next := control.Revision{Number: 2, Gateway: "secret-new", Rules: "[]"}
	if err = s.Save(ctx, control.Journal{Applied: control.Revision{Number: 1, Gateway: "secret-old"}, Pending: &next}); err != nil {
		t.Fatal(err)
	}
	if err = s.Save(ctx, control.Journal{Applied: next}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.db.QueryContext(ctx, "SELECT state,summary FROM config_events ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	var states []string
	for rows.Next() {
		var state, summary string
		if err = rows.Scan(&state, &summary); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(summary, "secret") {
			t.Fatal("审计泄漏原始配置")
		}
		states = append(states, state)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	if strings.Join(states, ",") != "prepared,applied" {
		t.Fatal("审计状态链不完整", states)
	}
	third := control.Revision{Number: 3}
	if err = s.Save(ctx, control.Journal{Applied: next, Pending: &third}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, "DROP TABLE config_events"); err != nil {
		t.Fatal(err)
	}
	if err = s.Save(ctx, control.Journal{Applied: control.Revision{Number: 3}}); err == nil {
		t.Fatal("审计写失败未报告")
	}
	j, err := s.Load(ctx)
	if err != nil || j.Applied.Number != 2 {
		t.Fatal("审计失败后仍提交修订", j, err)
	}
}

func TestSeparateWriterCannotReplacePending(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "writers.db")
	a, err := OpenJournal(ctx, path, control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenJournal(ctx, path, control.Revision{Number: 99})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	first := control.Revision{Number: 2, Gateway: "first"}
	second := control.Revision{Number: 2, Gateway: "second"}
	if err = a.Save(ctx, control.Journal{Applied: control.Revision{Number: 1}, Pending: &first}); err != nil {
		t.Fatal(err)
	}
	if err = b.Save(ctx, control.Journal{Applied: control.Revision{Number: 1}, Pending: &second}); err == nil {
		t.Fatal("第二个写入者覆盖了未完成事务")
	}
	if err = a.Save(ctx, control.Journal{Applied: first}); err != nil {
		t.Fatal(err)
	}
	if err = b.Save(ctx, control.Journal{Applied: control.Revision{Number: 1}, Pending: &second}); err == nil {
		t.Fatal("过时快照覆盖了已提交事务")
	}
	j, err := a.Load(ctx)
	if err != nil || j.Applied.Gateway != "first" || j.Pending != nil {
		t.Fatal("多写入者破坏修订", j, err)
	}
}

type engine struct{ value string }

func (e *engine) Check(context.Context, string) error         { return nil }
func (e *engine) Apply(_ context.Context, value string) error { e.value = value; return nil }

func TestDurableRecovery(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"prepared", "gateway", "vpn"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.db")
			old := control.Revision{Number: 1, Gateway: "old-g", VPN: "old-v"}
			s, err := OpenJournal(ctx, path, old)
			if err != nil {
				t.Fatal(err)
			}
			next := control.Revision{Number: 2, Gateway: "new-g", VPN: "new-v"}
			if err = s.Save(ctx, control.Journal{Applied: old, Pending: &next}); err != nil {
				t.Fatal(err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			// 重开真实磁盘数据库，并提供不同默认值，确认不会覆盖已有日志。
			s, err = OpenJournal(ctx, path, control.Revision{Number: 99})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			g, v := &engine{value: "old-g"}, &engine{value: "old-v"}
			if stage != "prepared" {
				g.value = "new-g"
			}
			if stage == "vpn" {
				v.value = "new-v"
			}
			if err = control.NewCoordinator(s, g, v).Recover(ctx); err != nil {
				t.Fatal(err)
			}
			j, err := s.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if j.Pending != nil || j.Applied.Number != 1 || g.value != "old-g" || v.value != "old-v" {
				t.Fatal("磁盘日志恢复不一致")
			}
		})
	}
}

func TestInvalidJournalAndFutureSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := OpenJournal(ctx, path, control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	n := control.Revision{Number: 8}
	if err = s.Save(ctx, control.Journal{Applied: control.Revision{Number: 1}, Pending: &n}); err == nil {
		t.Fatal("未拒绝不连续修订")
	}
	if _, err = s.db.ExecContext(ctx, "PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if opened, err := OpenJournal(ctx, path, control.Revision{}); err == nil {
		opened.Close()
		t.Fatal("未拒绝未来数据库版本")
	}
}

func TestVersionOneMigrationRetainsJournal(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v1.db")
	old := control.Revision{Number: 7, Gateway: "existing-g", VPN: "existing-v"}
	s, err := OpenJournal(ctx, path, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, "DROP TABLE administrator"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.ExecContext(ctx, "PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenJournal(ctx, path, control.Revision{Number: 99})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	j, err := s.Load(ctx)
	if err != nil || j.Applied != old {
		t.Fatal("迁移覆盖旧修订", j, err)
	}
	if ready, err := s.Initialized(ctx); err != nil || ready {
		t.Fatal("迁移误建管理员或缺少新表", err)
	}
}

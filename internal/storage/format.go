package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

// RequiredJournalVersion 防止旧程序忽略HTTPS字段后把入口重编译为明文。
// 准备中的修订也要提前升级格式，崩溃恢复不能交给不识别TLS语义的旧程序。
func RequiredJournalVersion(j control.Journal) (int, error) {
	version := 2
	revisions := []control.Revision{j.Applied}
	if j.Pending != nil {
		revisions = append(revisions, *j.Pending)
	}
	for _, revision := range revisions {
		if revision.Settings != "" && version < 3 {
			version = 3
		}
		if revision.Rules == "" {
			continue
		}
		var rules []struct {
			HTTPS bool `json:"https"`
		}
		if err := json.Unmarshal([]byte(revision.Rules), &rules); err != nil {
			return 0, err
		}
		for _, rule := range rules {
			if rule.HTTPS {
				version = 4
			}
		}
	}
	return version, nil
}

// DowngradeHTTPFormat 仅供持有独占维护锁的离线工具调用，不改变业务或认证记录。
// 撤销所有HTTPS规则且不存在准备中修订后，才能允许旧程序重新读取数据库。
func (s *JournalStore) DowngradeHTTPFormat(ctx context.Context) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var raw string
	if err = tx.QueryRowContext(ctx, "SELECT body FROM revision_journal WHERE id=1").Scan(&raw); err != nil {
		return 0, err
	}
	var journal control.Journal
	if err = json.Unmarshal([]byte(raw), &journal); err != nil {
		return 0, err
	}
	if journal.Pending != nil {
		return 0, errors.New("请先完成或撤回准备中的修订")
	}
	required, err := RequiredJournalVersion(journal)
	if err != nil {
		return 0, err
	}
	if required >= 4 {
		return 0, errors.New("请先通过后台撤销所有HTTPS规则，不能降级为明文")
	}
	var version int
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return 0, err
	}
	if version > 4 {
		return 0, errors.New("未知新格式不能由本工具降级")
	}
	if _, err = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", required)); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO config_events(created_utc,revision,state,summary) VALUES(strftime('%Y-%m-%dT%H:%M:%fZ','now'),?,'format_rollback','离线验证无HTTPS规则后降低兼容格式')", journal.Applied.Number); err != nil {
		return 0, err
	}
	return required, tx.Commit()
}

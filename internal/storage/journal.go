// Package storage 管理 SQLite 持久化，不向上层暴露 SQL 字符串。
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	_ "modernc.org/sqlite" // 注册纯 Go 驱动，镜像无需外部 SQLite 动态库。
)

// JournalStore 通过 SQLite 完整同步事务保存配置修订日志。
type JournalStore struct{ db *sql.DB }

// OpenJournal 初始化或打开数据库；不覆盖已有修订，拒绝未知的新 schema。
func OpenJournal(ctx context.Context, path string, initial control.Revision) (*JournalStore, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &JournalStore{db: db}
	if err = s.initialize(ctx, initial); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *JournalStore) initialize(ctx context.Context, initial control.Revision) error {
	var version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 4 {
		return errors.New("数据库版本高于当前程序支持的版本")
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA journal_mode=WAL"); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS revision_journal (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL CHECK(json_valid(body)))"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS administrator (id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL, secret BLOB NOT NULL, last_counter INTEGER NOT NULL, recovery TEXT NOT NULL CHECK(json_valid(recovery)))"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS bootstrap_state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL CHECK(json_valid(body)))"); err != nil {
		return err
	}
	// 可选附加表不改变已有凭据/修订格式，兼容性版本仍为2，允许回退到认证阶段镜像。
	if _, err = tx.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS config_events (id INTEGER PRIMARY KEY AUTOINCREMENT, created_utc TEXT NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL, summary TEXT NOT NULL)"); err != nil {
		return err
	}
	b, err := json.Marshal(control.Journal{Applied: initial})
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO revision_journal(id,body) VALUES(1,?) ON CONFLICT(id) DO NOTHING", string(b)); err != nil {
		return err
	}
	var currentRaw string
	if err = tx.QueryRowContext(ctx, "SELECT body FROM revision_journal WHERE id=1").Scan(&currentRaw); err != nil {
		return err
	}
	var current control.Journal
	if err = json.Unmarshal([]byte(currentRaw), &current); err != nil {
		return err
	}
	if version < 2 {
		version = 2
	}
	// 写入可变业务设置后拒绝旧程序打开，避免旧Revision结构丢弃未知字段后回写。
	required, err := RequiredJournalVersion(current)
	if err != nil {
		return err
	}
	if required > version {
		version = required
	}
	if _, err = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", version)); err != nil {
		return err
	}
	return tx.Commit()
}

// Close 释放连接；停止服务时先结束写入再关闭。
func (s *JournalStore) Close() error { return s.db.Close() }

// Load 读取一致的修订日志，数据损坏时返回错误而非生成默认配置。
func (s *JournalStore) Load(ctx context.Context) (control.Journal, error) {
	var body string
	var j control.Journal
	if err := s.db.QueryRowContext(ctx, "SELECT body FROM revision_journal WHERE id=1").Scan(&body); err != nil {
		return j, err
	}
	err := json.Unmarshal([]byte(body), &j)
	return j, err
}

// Save 使用单条原子更新，返回成功意味着事务已提交到 SQLite。
func (s *JournalStore) Save(ctx context.Context, j control.Journal) error {
	if j.Pending != nil && j.Pending.Number != j.Applied.Number+1 {
		return errors.New("待应用修订号不连续")
	}
	body, err := json.Marshal(j)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previousRaw string
	if err = tx.QueryRowContext(ctx, "SELECT body FROM revision_journal WHERE id=1").Scan(&previousRaw); err != nil {
		return err
	}
	var previous control.Journal
	if err = json.Unmarshal([]byte(previousRaw), &previous); err != nil {
		return err
	}
	// 不仅依赖进程内锁：拒绝另一进程以过时快照覆盖准备中或已提交的修订。
	if j.Pending != nil {
		if j.Applied != previous.Applied || (previous.Pending != nil && *previous.Pending != *j.Pending) {
			return control.ErrRevisionConflict
		}
	} else if previous.Pending != nil {
		if j.Applied != previous.Applied && j.Applied != *previous.Pending {
			return control.ErrRevisionConflict
		}
	} else if j.Applied != previous.Applied {
		bootstrap := previous.Applied.Gateway == "" && j.Applied.Number == previous.Applied.Number && j.Applied.VPN == previous.Applied.VPN && j.Applied.Settings == previous.Applied.Settings && (j.Applied.Rules == "[]" || j.Applied.Rules == "")
		if !bootstrap {
			return control.ErrRevisionConflict
		}
	}
	state := "snapshot"
	revision := j.Applied.Number
	if j.Pending != nil {
		state = "prepared"
		revision = j.Pending.Number
	} else if previous.Pending != nil {
		state = "rolled_back"
		revision = previous.Pending.Number
		if j.Applied.Number > previous.Applied.Number {
			state = "applied"
		}
	}
	var rules []json.RawMessage
	if j.Applied.Rules != "" {
		if err = json.Unmarshal([]byte(j.Applied.Rules), &rules); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, "UPDATE revision_journal SET body=? WHERE id=1", string(body))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("修订日志缺失")
	}
	required, err := RequiredJournalVersion(j)
	if err != nil {
		return err
	}
	var version int
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if required > version {
		if _, err = tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version=%d", required)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO config_events(created_utc,revision,state,summary) VALUES(strftime('%Y-%m-%dT%H:%M:%fZ','now'),?,?,?)", revision, state, fmt.Sprintf("已提交%d条业务规则", len(rules))); err != nil {
		return err
	}
	// 限制审计条目数量，避免配置探针和长期运行造成无界增长。
	if _, err = tx.ExecContext(ctx, "DELETE FROM config_events WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM config_events)"); err != nil {
		return err
	}
	return tx.Commit()
}

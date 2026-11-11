// Package storage 管理 SQLite 持久化，不向上层暴露 SQL 字符串。
package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	if version > 2 {
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
	b, err := json.Marshal(control.Journal{Applied: initial})
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO revision_journal(id,body) VALUES(1,?) ON CONFLICT(id) DO NOTHING", string(b)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
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
	result, err := s.db.ExecContext(ctx, "UPDATE revision_journal SET body=? WHERE id=1", string(body))
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
	return nil
}

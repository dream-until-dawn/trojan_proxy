package webaccess

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrRevision = errors.New("访问白名单修订已变化，请刷新")

// Store 独立访问库，1GiB容量上限；失败不能回滚认证或业务配置。
type Store struct{ db *sql.DB }

func Open(ctx context.Context, path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if filepath.Base(abs) != "access.db" {
		return nil, errors.New("访问记录必须使用独立access.db")
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(250)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Store, error) { db.Close(); return nil, e }
	var version, size int64
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fail(err)
	}
	if version > 1 {
		return fail(errors.New("访问库版本高于当前支持"))
	}
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size); err != nil {
		return fail(err)
	}
	if size < 512 || size > 65536 {
		return fail(errors.New("访问库页大小无效"))
	}
	for _, statement := range []string{"PRAGMA auto_vacuum=INCREMENTAL", "PRAGMA journal_mode=WAL", "PRAGMA secure_delete=ON", "PRAGMA wal_autocheckpoint=128", "PRAGMA journal_size_limit=16777216", fmt.Sprintf("PRAGMA max_page_count=%d", (1<<30)/size),
		`CREATE TABLE IF NOT EXISTS policy(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL,cidrs TEXT NOT NULL)`,
		`INSERT OR IGNORE INTO policy VALUES(1,1,'[]')`,
		`CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY,source TEXT NOT NULL,generation INTEGER NOT NULL,position INTEGER NOT NULL,at INTEGER NOT NULL,ip TEXT NOT NULL,family INTEGER NOT NULL,address BLOB NOT NULL,host TEXT NOT NULL,port INTEGER NOT NULL,method TEXT NOT NULL,path TEXT NOT NULL,status INTEGER NOT NULL,duration REAL NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,UNIQUE(source,generation,position))`,
		`CREATE INDEX IF NOT EXISTS requests_time ON requests(at)`, `CREATE INDEX IF NOT EXISTS requests_ip ON requests(ip,at)`,
		`CREATE TABLE IF NOT EXISTS cursors(source TEXT PRIMARY KEY,offset INTEGER NOT NULL,size INTEGER NOT NULL,generation INTEGER NOT NULL,last_seen INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS diagnostics(id INTEGER PRIMARY KEY CHECK(id=1),invalid INTEGER NOT NULL,gaps INTEGER NOT NULL,last_tick INTEGER NOT NULL)`, `INSERT OR IGNORE INTO diagnostics VALUES(1,0,0,0)`, "PRAGMA user_version=1"} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			return fail(err)
		}
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }

type policyReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readPolicy(ctx context.Context, db policyReader) (Policy, error) {
	var p Policy
	var raw string
	err := db.QueryRowContext(ctx, "SELECT revision,cidrs FROM policy WHERE id=1").Scan(&p.Revision, &raw)
	if err == nil {
		err = json.Unmarshal([]byte(raw), &p.CIDRs)
	}
	if err == nil {
		p.CIDRs, err = NormalizeWhitelist(p.CIDRs)
	}
	return p, err
}
func (s *Store) Policy(ctx context.Context) (Policy, error) { return readPolicy(ctx, s.db) }

func prune(ctx context.Context, tx *sql.Tx, p Policy, now time.Time) error {
	trusted, args := whitelistSQL(p.CIDRs)
	params := []any{now.Add(-OtherRetention).UnixMilli()}
	params = append(params, args...)
	params = append(params, now.Add(-TrustedRetention).UnixMilli())
	_, err := tx.ExecContext(ctx, "DELETE FROM requests WHERE at<=? OR ("+trusted+" AND at<=?)", params...)
	return err
}
func (s *Store) SetWhitelist(ctx context.Context, expected uint64, values []string, now time.Time) error {
	values, err := NormalizeWhitelist(values)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := readPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if p.Revision != expected {
		return ErrRevision
	}
	p.Revision++
	p.CIDRs = values
	raw, _ := json.Marshal(values)
	if _, err = tx.ExecContext(ctx, "UPDATE policy SET revision=?,cidrs=? WHERE id=1", p.Revision, string(raw)); err != nil {
		return err
	}
	if err = prune(ctx, tx, p, now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Prune(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := readPolicy(ctx, tx)
	if err != nil {
		return err
	}
	if err = prune(ctx, tx, p, now); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM cursors WHERE last_seen<?", now.Add(-OtherRetention).UnixMilli()); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "PRAGMA incremental_vacuum(256)")
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return err
}
func (s *Store) Cursor(ctx context.Context, source string) (Cursor, error) {
	var c Cursor
	err := s.db.QueryRowContext(ctx, "SELECT offset,size,generation FROM cursors WHERE source=?", source).Scan(&c.Offset, &c.Size, &c.Generation)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	return c, err
}

// Ingest 同事务写明细和游标，未完成尾行不会提前推进；合法重放不重复计数。
func (s *Store) Ingest(ctx context.Context, source string, start, end, size int64, records []Record, positions []int64, invalid int, now time.Time) error {
	if source == "" || len(source) > 160 || invalid < 0 || start < 0 || end < start || size < end || len(records) != len(positions) || len(records) > 512 {
		return errors.New("访问采集批次无效")
	}
	for i, position := range positions {
		if position < start || position >= end || (i > 0 && position <= positions[i-1]) {
			return errors.New("访问行偏移无效")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var c Cursor
	err = tx.QueryRowContext(ctx, "SELECT offset,size,generation FROM cursors WHERE source=?", source).Scan(&c.Offset, &c.Size, &c.Generation)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if start != c.Offset {
		if end <= c.Offset {
			return nil
		}
		return errors.New("访问采集游标冲突")
	}
	for i, r := range records {
		if err = validateRecord(r, now); err != nil {
			return err
		}
		ip, err := netip.ParseAddr(r.IP)
		if err != nil {
			return err
		}
		ip = ip.Unmap()
		raw := ip.As16()
		family := 6
		if ip.Is4() {
			family = 4
		}
		if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO requests(source,generation,position,at,ip,family,address,host,port,method,path,status,duration,upload,download) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, source, c.Generation, positions[i], r.At, ip.String(), family, raw[:], r.Host, r.Port, r.Method, r.Path, r.Status, r.DurationMS, r.Upload, r.Download); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO cursors VALUES(?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET offset=excluded.offset,size=excluded.size,last_seen=excluded.last_seen`, source, end, size, c.Generation, now.UnixMilli()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE diagnostics SET invalid=invalid+? WHERE id=1", invalid); err != nil {
		return err
	}
	return tx.Commit()
}

// NoteCollection 记录采集间断或已知未读文件丢失；不把缺数据伪装成零请求。
func (s *Store) NoteCollection(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var last int64
	if err = tx.QueryRowContext(ctx, "SELECT last_tick FROM diagnostics WHERE id=1").Scan(&last); err != nil {
		return err
	}
	gap := 0
	if last > 0 && now.UnixMilli()-last > 60000 {
		gap = 1
	}
	var missing int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM cursors WHERE last_seen<? AND offset<size", now.Add(-5*time.Second).UnixMilli()).Scan(&missing); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE cursors SET size=offset WHERE last_seen<? AND offset<size", now.Add(-5*time.Second).UnixMilli()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE diagnostics SET gaps=gaps+?,last_tick=? WHERE id=1", gap+missing, now.UnixMilli()); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) Diagnostics(ctx context.Context) (int64, int64, error) {
	var invalid, gaps int64
	err := s.db.QueryRowContext(ctx, "SELECT invalid,gaps FROM diagnostics WHERE id=1").Scan(&invalid, &gaps)
	return invalid, gaps, err
}

// Truncated 标记不受支持的原位截断；新代数防止新请求与旧文件偏移冲突。
func (s *Store) Truncated(ctx context.Context, source string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE cursors SET offset=0,size=0,generation=generation+1 WHERE source=?", source); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE diagnostics SET gaps=gaps+1 WHERE id=1"); err != nil {
		return err
	}
	return tx.Commit()
}

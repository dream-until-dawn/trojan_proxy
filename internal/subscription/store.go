// Package subscription 提供与管理员会话隔离的只读VPN订阅授权。
package subscription

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

var (
	ErrDenied      = errors.New("订阅不存在或已失效")
	ErrUnavailable = errors.New("订阅服务暂不可用")
	ErrLimit       = errors.New("有效订阅已达16个或请求正在处理")
	ErrName        = errors.New("设备名称须为1至40个可见字符")
)

// Record 仅包含非秘密元数据，不返回令牌或其摘要。
type Record struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Store 使用独立小型数据库；原始令牌从不写盘。
type Store struct {
	db  *sql.DB
	mu  sync.Mutex
	now func() time.Time
}

// Open 只允许专用subscription.db，拒绝链接文件，并限制数据库容量。
func Open(ctx context.Context, path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if filepath.Base(abs) != "subscription.db" {
		return nil, ErrUnavailable
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	if info, e := os.Lstat(abs); e == nil && !info.Mode().IsRegular() {
		return nil, ErrUnavailable
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
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
	q.Add("_pragma", "busy_timeout(250)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	failed := true
	defer func() {
		if failed {
			db.Close()
		}
	}()
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version > 1 {
		return nil, ErrUnavailable
	}
	for _, statement := range []string{"PRAGMA journal_mode=DELETE", "PRAGMA max_page_count=1024", "PRAGMA secure_delete=ON", `CREATE TABLE IF NOT EXISTS tokens(id TEXT PRIMARY KEY,name TEXT NOT NULL,digest TEXT UNIQUE NOT NULL,owner TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,revoked INTEGER NOT NULL CHECK(revoked IN (0,1)))`, "PRAGMA user_version=1"} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			return nil, err
		}
	}
	failed = false
	return &Store{db: db, now: time.Now}, nil
}

// Close 释放独立订阅连接。
func (s *Store) Close() error { return s.db.Close() }

func randomString(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func tokenDigest(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func validToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == token
}
func validOwner(owner string) bool {
	b, err := hex.DecodeString(owner)
	return err == nil && len(b) == 32
}

// Create 在短事务中限制有效设备数，返回只显示一次的原始令牌。
func (s *Store) Create(ctx context.Context, owner, name string) (Record, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 40 || strings.ContainsFunc(name, unicode.IsControl) {
		return Record{}, "", ErrName
	}
	if !validOwner(owner) {
		return Record{}, "", ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC().Truncate(time.Second)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, "", ErrUnavailable
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM tokens WHERE owner<>? OR revoked=1 OR expires<=?", owner, now.Unix()); err != nil {
		return Record{}, "", ErrUnavailable
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM tokens").Scan(&count); err != nil {
		return Record{}, "", ErrUnavailable
	}
	if count >= 16 {
		return Record{}, "", ErrLimit
	}
	id, err := randomString(16)
	if err != nil {
		return Record{}, "", ErrUnavailable
	}
	token, err := randomString(32)
	if err != nil {
		return Record{}, "", ErrUnavailable
	}
	record := Record{ID: id, Name: name, CreatedAt: now, ExpiresAt: now.Add(365 * 24 * time.Hour)}
	if _, err = tx.ExecContext(ctx, "INSERT INTO tokens(id,name,digest,owner,created,expires,revoked) VALUES(?,?,?,?,?,?,0)", id, name, tokenDigest(token), owner, now.Unix(), record.ExpiresAt.Unix()); err != nil {
		return Record{}, "", ErrUnavailable
	}
	if err = tx.Commit(); err != nil {
		return Record{}, "", ErrUnavailable
	}
	return record, token, nil
}

// List 只列出当前管理员代次的有效订阅，不暴露摘要。
func (s *Store) List(ctx context.Context, owner string) ([]Record, error) {
	if !validOwner(owner) {
		return nil, ErrUnavailable
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,name,created,expires FROM tokens WHERE owner=? AND revoked=0 AND expires>? ORDER BY created,id", owner, s.now().Unix())
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	result := []Record{}
	for rows.Next() {
		var r Record
		var created, expires int64
		if err = rows.Scan(&r.ID, &r.Name, &created, &expires); err != nil {
			return nil, ErrUnavailable
		}
		r.CreatedAt = time.Unix(created, 0).UTC()
		r.ExpiresAt = time.Unix(expires, 0).UTC()
		result = append(result, r)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	return result, nil
}

// Revoke 只撤销当前代次指定设备，重复撤销返回统一不存在错误。
func (s *Store) Revoke(ctx context.Context, owner, id string) error {
	if !validOwner(owner) {
		return ErrUnavailable
	}
	result, err := s.db.ExecContext(ctx, "UPDATE tokens SET revoked=1 WHERE id=? AND owner=? AND revoked=0", id, owner)
	if err != nil {
		return ErrUnavailable
	}
	n, err := result.RowsAffected()
	if err != nil {
		return ErrUnavailable
	}
	if n != 1 {
		return ErrDenied
	}
	return nil
}

// Validate 对错误、撤销、过期和旧管理员代次使用同一拒绝结果。
func (s *Store) Validate(ctx context.Context, owner, token string) error {
	if !validOwner(owner) {
		return ErrUnavailable
	}
	if !validToken(token) {
		return ErrDenied
	}
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM tokens WHERE digest=? AND owner=? AND revoked=0 AND expires>?", tokenDigest(token), owner, s.now().Unix()).Scan(&count)
	if err != nil {
		return ErrUnavailable
	}
	if count != 1 {
		return ErrDenied
	}
	return nil
}

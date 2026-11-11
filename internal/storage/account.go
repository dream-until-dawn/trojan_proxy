package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// Account 只包含散列或密文，不含可直接登录的会话令牌。
type Account struct {
	PasswordHash string
	Secret       []byte
	LastCounter  int64
	Recovery     []string
}

// Account 读取唯一管理员；未初始化返回 sql.ErrNoRows。
func (s *JournalStore) Account(ctx context.Context) (Account, error) {
	var a Account
	var recovery string
	err := s.db.QueryRowContext(ctx, "SELECT password_hash,secret,last_counter,recovery FROM administrator WHERE id=1").Scan(&a.PasswordHash, &a.Secret, &a.LastCounter, &recovery)
	if err != nil {
		return a, err
	}
	err = json.Unmarshal([]byte(recovery), &a.Recovery)
	return a, err
}

// CreateAccount 仅首次初始化成功，绝不覆盖已有管理员。
func (s *JournalStore) CreateAccount(ctx context.Context, a Account) error {
	if a.PasswordHash == "" || len(a.Secret) == 0 {
		return errors.New("管理员凭据不完整")
	}
	r, err := json.Marshal(a.Recovery)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, "INSERT INTO administrator(id,password_hash,secret,last_counter,recovery) VALUES(1,?,?,?,?)", a.PasswordHash, a.Secret, a.LastCounter, string(r))
	return err
}

// ConsumeTOTP 原子推进步长，竞争或重放返回 false。
func (s *JournalStore) ConsumeTOTP(ctx context.Context, previous, next int64) (bool, error) {
	if next <= previous {
		return false, nil
	}
	r, err := s.db.ExecContext(ctx, "UPDATE administrator SET last_counter=? WHERE id=1 AND last_counter=?", next, previous)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	return n == 1, err
}

// ConsumeRecovery 原子移除一个恢复码散列，即使多个进程同时验证也只能成功一次。
func (s *JournalStore) ConsumeRecovery(ctx context.Context, hash string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var raw string
	if err = tx.QueryRowContext(ctx, "SELECT recovery FROM administrator WHERE id=1").Scan(&raw); err != nil {
		return false, err
	}
	var hashes []string
	if err = json.Unmarshal([]byte(raw), &hashes); err != nil {
		return false, err
	}
	found := -1
	for i, h := range hashes {
		if h == hash {
			found = i
			break
		}
	}
	if found < 0 {
		return false, nil
	}
	hashes = append(hashes[:found], hashes[found+1:]...)
	body, err := json.Marshal(hashes)
	if err != nil {
		return false, err
	}
	r, err := tx.ExecContext(ctx, "UPDATE administrator SET recovery=? WHERE id=1 AND recovery=?", string(body), raw)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	if err != nil || n != 1 {
		return false, err
	}
	return true, tx.Commit()
}

// Initialized 区分尚未初始化与数据库读取故障；不能把故障当成允许重新注册。
func (s *JournalStore) Initialized(ctx context.Context) (bool, error) {
	_, err := s.Account(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

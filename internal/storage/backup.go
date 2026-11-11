package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// BackupInto 通过SQLite一致性副本备份正在运行的库，不复制可能不同步的WAL文件。
func (s *JournalStore) BackupInto(ctx context.Context, destination string) error {
	abs, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if _, err = s.db.ExecContext(ctx, "VACUUM INTO ?", abs); err != nil {
		os.Remove(abs)
		return err
	}
	info, err := os.Stat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("数据库备份副本不可用")
	}
	return os.Chmod(abs, 0600)
}

// ResetAccount 仅供独占维护锁内的SSH恢复使用；不修改主密钥或业务修订。
func (s *JournalStore) ResetAccount(ctx context.Context, account Account) error {
	if account.PasswordHash == "" || len(account.Secret) == 0 || len(account.Recovery) != 8 || account.LastCounter < 0 {
		return errors.New("恢复账户材料不完整")
	}
	return s.resetAccount(ctx, account)
}

func (s *JournalStore) resetAccount(ctx context.Context, a Account) error {
	raw, err := json.Marshal(a.Recovery)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE administrator SET password_hash=?,secret=?,last_counter=?,recovery=? WHERE id=1", a.PasswordHash, a.Secret, a.LastCounter, string(raw))
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("没有可以恢复的管理员")
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM bootstrap_state"); err != nil {
		return err
	}
	return tx.Commit()
}

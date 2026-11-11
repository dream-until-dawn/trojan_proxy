package storage

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ErrSetupState 隐藏过期、竞争和已初始化之间的差异，避免重新注册现有账户。
var ErrSetupState = errors.New("初始化令牌无效、已过期或管理员已存在")

// SetupState 仅用于受限存储；秘密为密文，凭据和会话仅保存散列。
type SetupState struct {
	TokenHash   string
	SessionHash string
	Expires     int64
	Failures    int
	Account     Account
}

// IssueSetup 由本机命令调用；重新签发会使尚未完成的旧绑定失效。
func (s *JournalStore) IssueSetup(ctx context.Context, tokenHash string, expires time.Time) error {
	if len(tokenHash) != 64 {
		return ErrSetupState
	}
	body, err := json.Marshal(SetupState{TokenHash: tokenHash, Expires: expires.Unix()})
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `INSERT INTO bootstrap_state(id,body)
	 SELECT 1,? WHERE NOT EXISTS(SELECT 1 FROM administrator)
	 ON CONFLICT(id) DO UPDATE SET body=excluded.body
	 WHERE NOT EXISTS(SELECT 1 FROM administrator)`, string(body))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		err = ErrSetupState
	}
	return err
}

// Setup 仅读取没有管理员且仍在有效期内的绑定，数据库异常不会变成可初始化状态。
func (s *JournalStore) Setup(ctx context.Context, now time.Time) (SetupState, error) {
	var body string
	var state SetupState
	err := s.db.QueryRowContext(ctx, `SELECT body FROM bootstrap_state WHERE id=1
	 AND NOT EXISTS(SELECT 1 FROM administrator) AND json_extract(body,'$.Expires')>?`, now.Unix()).Scan(&body)
	if err != nil {
		return state, ErrSetupState
	}
	if err = json.Unmarshal([]byte(body), &state); err != nil {
		return SetupState{}, err
	}
	return state, nil
}

// SwapSetup 使用完整旧快照条件更新，跨进程也不能重复消费同一令牌。
func (s *JournalStore) SwapSetup(ctx context.Context, previous, next SetupState, now time.Time) error {
	before, err := json.Marshal(previous)
	if err != nil {
		return err
	}
	after, err := json.Marshal(next)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE bootstrap_state SET body=? WHERE id=1 AND body=?
	 AND json_extract(body,'$.Expires')>? AND NOT EXISTS(SELECT 1 FROM administrator)`, string(after), string(before), now.Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		err = ErrSetupState
	}
	return err
}

// CompleteSetup 在同一事务创建唯一账户并移除绑定；终端初始化竞争同样由唯一约束兜底。
func (s *JournalStore) CompleteSetup(ctx context.Context, state SetupState, counter int64, now time.Time) error {
	if state.SessionHash == "" || state.Account.PasswordHash == "" || len(state.Account.Secret) == 0 || counter < 0 {
		return ErrSetupState
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	recovery, err := json.Marshal(state.Account.Recovery)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO administrator(id,password_hash,secret,last_counter,recovery)
	 SELECT 1,?,?,?,? WHERE EXISTS(SELECT 1 FROM bootstrap_state WHERE id=1 AND body=?
	 AND json_extract(body,'$.Expires')>?) AND NOT EXISTS(SELECT 1 FROM administrator)`,
		state.Account.PasswordHash, state.Account.Secret, counter, string(recovery), string(body), now.Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrSetupState
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM bootstrap_state WHERE id=1"); err != nil {
		return err
	}
	return tx.Commit()
}

// HasSetup 检查是否有依赖原主密钥的未完成草稿，禁止主密钥丢失后静默换密钥。
func (s *JournalStore) HasSetup(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM bootstrap_state").Scan(&count)
	return count != 0, err
}

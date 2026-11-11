// Package traffic 独立保存受限分钟统计，不访问认证或业务修订数据库。
package traffic

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Retention 是固定滚动窗口，后台不允许将它调长。
const Retention = 30 * 24 * time.Hour

var instancePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// Delta 的空Target、all协议代表全局行，不能与目的明细一起相加。
type Delta struct {
	Bucket      int64  `json:"bucket"`
	Network     string `json:"network"`
	Target      string `json:"target"`
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
	Connections int64  `json:"connections"`
	ObservedMS  int64  `json:"observed_ms"`
	Gap         bool   `json:"gap"`
}

// Batch 的序号按引擎实例递增，重复或过期批次不再次计费。
type Batch struct {
	Instance string  `json:"instance"`
	Sequence int64   `json:"sequence"`
	Rows     []Delta `json:"rows"`
}

// Store 使用独立连接与短写入预算，统计不可用时调用方必须降级而非中止代理。
type Store struct {
	db   *sql.DB
	path string
}

// Open 设置WAL及256MiB页数上限；调用方负责生命周期和定时清理。
func Open(ctx context.Context, path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if filepath.Base(abs) != "traffic.db" {
		return nil, errors.New("统计只能使用独立traffic.db文件")
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
	q.Add("_pragma", "busy_timeout(250)")
	q.Add("_pragma", "synchronous(FULL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: abs}
	var version int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version > 1 {
		db.Close()
		return nil, errors.New("统计数据库版本不可用")
	}
	var pageSize int64
	if err = db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err != nil || pageSize < 512 || pageSize > 65536 {
		db.Close()
		return nil, errors.New("统计数据库页大小异常")
	}
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL", fmt.Sprintf("PRAGMA max_page_count=%d", (256<<20)/pageSize),
		"PRAGMA wal_autocheckpoint=128", "PRAGMA journal_size_limit=16777216",
		"PRAGMA secure_delete=ON",
		`CREATE TABLE IF NOT EXISTS traffic_minute(bucket INTEGER NOT NULL,network TEXT NOT NULL,target TEXT NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL,connections INTEGER NOT NULL,observed_ms INTEGER NOT NULL,gap INTEGER NOT NULL,PRIMARY KEY(bucket,network,target)) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS traffic_instances(instance TEXT PRIMARY KEY,sequence INTEGER NOT NULL,last_seen INTEGER NOT NULL) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS traffic_meta(id INTEGER PRIMARY KEY CHECK(id=1),discarded_through INTEGER NOT NULL)`,
		`INSERT INTO traffic_meta(id,discarded_through) VALUES(1,-1) ON CONFLICT(id) DO NOTHING`,
		"PRAGMA user_version=1",
	} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close 不自动导出统计，备份不应包含此数据库或WAL。
func (s *Store) Close() error { return s.db.Close() }

func validRow(row Delta, now time.Time) bool {
	if row.Bucket%60 != 0 || row.Bucket > now.Unix()+60 || row.Upload < 0 || row.Download < 0 || row.Connections < 0 || row.Upload > 1<<50 || row.Download > 1<<50 || row.Connections > 1<<30 || row.ObservedMS < 0 || row.ObservedMS > 60000 {
		return false
	}
	if row.Network == "all" {
		return row.Target == ""
	}
	if (row.Network != "tcp" && row.Network != "udp") || row.ObservedMS != 0 {
		return false
	}
	address, err := netip.ParseAddrPort(row.Target)
	return err == nil && address.Port() != 0 && address.Addr().Zone() == "" && netip.AddrPortFrom(address.Addr().Unmap(), address.Port()).String() == row.Target
}

// Append 在同一事务内去重和累计，缺序标记缺口；不允许坏行造成部分写入。
func (s *Store) Append(ctx context.Context, batch Batch, now time.Time) error {
	if info, err := os.Stat(s.path + "-wal"); err == nil && info.Size() > 16<<20 {
		return errors.New("统计WAL达到预算，等待清理后恢复采集")
	}
	if !instancePattern.MatchString(batch.Instance) || batch.Sequence <= 0 || len(batch.Rows) > 512 {
		return errors.New("统计批次格式错误")
	}
	seen := map[string]bool{}
	global := map[int64]Delta{}
	details := map[int64]Delta{}
	for _, row := range batch.Rows {
		if !validRow(row, now) {
			return errors.New("统计行格式或时间异常")
		}
		key := fmt.Sprintf("%d/%s/%s", row.Bucket, row.Network, row.Target)
		if seen[key] {
			return errors.New("统计批次内包含重复行")
		}
		seen[key] = true
		if row.Network == "all" {
			global[row.Bucket] = row
		} else {
			sum := details[row.Bucket]
			sum.Upload += row.Upload
			sum.Download += row.Download
			sum.Connections += row.Connections
			details[row.Bucket] = sum
		}
	}
	for bucket, sum := range details {
		total, ok := global[bucket]
		if !ok || sum.Upload > total.Upload || sum.Download > total.Download || sum.Connections > total.Connections {
			return errors.New("统计全局行与目标明细不一致")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var previous int64
	err = tx.QueryRowContext(ctx, "SELECT sequence FROM traffic_instances WHERE instance=?", batch.Instance).Scan(&previous)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if batch.Sequence <= previous {
		return nil
	}
	gap := batch.Sequence != previous+1
	var discarded int64
	if err = tx.QueryRowContext(ctx, "SELECT discarded_through FROM traffic_meta WHERE id=1").Scan(&discarded); err != nil {
		return err
	}
	for _, row := range batch.Rows {
		if row.Bucket < now.Add(-Retention).Unix() || row.Bucket <= discarded {
			continue
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO traffic_minute(bucket,network,target,upload,download,connections,observed_ms,gap) VALUES(?,?,?,?,?,?,?,?)
		 ON CONFLICT(bucket,network,target) DO UPDATE SET upload=upload+excluded.upload,download=download+excluded.download,connections=connections+excluded.connections,observed_ms=min(60000,observed_ms+excluded.observed_ms),gap=max(gap,excluded.gap)`, row.Bucket, row.Network, row.Target, row.Upload, row.Download, row.Connections, row.ObservedMS, row.Gap || gap)
		if err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO traffic_instances(instance,sequence,last_seen) VALUES(?,?,?) ON CONFLICT(instance) DO UPDATE SET sequence=excluded.sequence,last_seen=excluded.last_seen`, batch.Instance, batch.Sequence, now.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// Clear 保留消费游标并屏蔽本分钟，以免尚在传输的旧批次把已清空数据重新写回。
func (s *Store) Clear(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "DELETE FROM traffic_minute"); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE traffic_meta SET discarded_through=max(discarded_through,?) WHERE id=1", now.Unix()/60*60); err != nil {
		return err
	}
	return tx.Commit()
}

// Totals 只统计全局行；Gap为真时界面必须明确表示采集缺口。
type Totals struct {
	Upload      int64 `json:"upload"`
	Download    int64 `json:"download"`
	Connections int64 `json:"connections"`
	ObservedMS  int64 `json:"observed_ms"`
	Gap         bool  `json:"gap"`
}

// Summary 无论调用者请求多早，仍强制使用滚动30天边界。
func (s *Store) Summary(ctx context.Context, from, until, now time.Time) (Totals, error) {
	if cutoff := now.Add(-Retention); from.Before(cutoff) {
		from = cutoff
	}
	if until.After(now) {
		until = now
	}
	var result Totals
	err := s.db.QueryRowContext(ctx, `SELECT coalesce(sum(upload),0),coalesce(sum(download),0),coalesce(sum(connections),0),coalesce(sum(observed_ms),0),coalesce(max(gap),0) FROM traffic_minute WHERE network='all' AND target='' AND bucket>=? AND bucket<=?`, from.Unix(), until.Unix()).Scan(&result.Upload, &result.Download, &result.Connections, &result.ObservedMS, &result.Gap)
	return result, err
}

// Purge 分批删除，调用方用受限context控制总时长；查询过滤不依赖清理是否已完成。
func (s *Store) Purge(ctx context.Context, now time.Time) error {
	cutoff := now.Add(-Retention).Unix()
	for {
		result, err := s.db.ExecContext(ctx, `DELETE FROM traffic_minute WHERE (bucket,network,target) IN (SELECT bucket,network,target FROM traffic_minute WHERE bucket<? LIMIT 5000)`, cutoff)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}
	}
	if _, err := s.db.ExecContext(ctx, "DELETE FROM traffic_instances WHERE last_seen<?", cutoff); err != nil {
		return err
	}
	var busy, log, checkpoint int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &checkpoint); err != nil {
		return err
	}
	if busy != 0 {
		return errors.New("统计WAL仍被读取，稍后重试清理")
	}
	return nil
}

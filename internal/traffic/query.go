package traffic

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Cursor 只恢复采集进度，避免控制面重启后把旧批次网速当作实时值。
func (s *Store) Cursor(ctx context.Context) (string, int64, error) {
	var instance string
	var sequence int64
	err := s.db.QueryRowContext(ctx, "SELECT instance,sequence FROM traffic_instances ORDER BY last_seen DESC LIMIT 1").Scan(&instance, &sequence)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return instance, sequence, err
}

// Dashboard 仅供鉴权后台使用，公共欢迎页不接触此类型。
type Dashboard struct {
	RetentionDays int            `json:"retention_days"`
	From          int64          `json:"from"`
	Until         int64          `json:"until"`
	Live          Live           `json:"live"`
	Totals        Totals         `json:"totals"`
	Targets       []TargetTotals `json:"targets"`
	Timeline      Series         `json:"timeline"`
}

// Dashboard 汇总请求有固定范围和分页上限，缺口字段必须保留到页面。
func (c *Collector) Dashboard(ctx context.Context, hours, offset int) (Dashboard, error) {
	if hours < 1 || hours > 720 {
		return Dashboard{}, errors.New("统计范围必须在1至720小时")
	}
	now := c.now()
	from := now.Add(-time.Duration(hours) * time.Hour)
	result := Dashboard{RetentionDays: 30, From: from.Unix(), Until: now.Unix(), Live: c.State()}
	var err error
	if result.Totals, err = c.store.Summary(ctx, from, now, now); err != nil {
		return result, err
	}
	if result.Targets, err = c.store.Targets(ctx, from, now, now, 100, offset); err != nil {
		return result, err
	}
	result.Timeline, err = c.store.Timeline(ctx, from, now, now)
	return result, err
}

// TargetTotals 按实际IP聚合其所有端口及TCP/UDP，不暴露访问内容。
type TargetTotals struct {
	IP          string `json:"ip"`
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
	Connections int64  `json:"connections"`
	Gap         bool   `json:"gap"`
}

func rangeBounds(from, until, now time.Time) (int64, int64) {
	if cutoff := now.Add(-Retention); from.Before(cutoff) {
		from = cutoff
	}
	if until.After(now) {
		until = now
	}
	return from.Unix(), until.Unix()
}

// Targets 强制30天边界，并限制分页，防止一次查询输出全部目的地址。
func (s *Store) Targets(ctx context.Context, from, until, now time.Time, limit, offset int) ([]TargetTotals, error) {
	if limit < 1 || limit > 200 || offset < 0 || offset > 10000 {
		return nil, errors.New("统计分页超出限制")
	}
	start, end := rangeBounds(from, until, now)
	rows, err := s.db.QueryContext(ctx, `SELECT CASE WHEN substr(target,1,1)='[' THEN substr(target,2,instr(target,']')-2) ELSE substr(target,1,instr(target,':')-1) END AS ip,sum(upload),sum(download),sum(connections),max(gap) FROM traffic_minute WHERE network!='all' AND bucket>=? AND bucket<=? GROUP BY ip ORDER BY sum(upload+download) DESC,ip LIMIT ? OFFSET ?`, start, end, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []TargetTotals{}
	for rows.Next() {
		var item TargetTotals
		if err = rows.Scan(&item.IP, &item.Upload, &item.Download, &item.Connections, &item.Gap); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// Point 只输出观察到的时间桶，不用补零掩盖缺失时间。
type Point struct {
	Bucket int64 `json:"bucket"`
	Totals
}
type Series struct {
	StepSeconds int64   `json:"step_seconds"`
	Points      []Point `json:"points"`
}

// Timeline 根据范围自动合并整分钟桶，最多输出约1000点；速率由实际采样毫秒计算。
func (s *Store) Timeline(ctx context.Context, from, until, now time.Time) (Series, error) {
	start, end := rangeBounds(from, until, now)
	step := int64(60)
	if end > start {
		step = ((end - start + 59999) / 60000) * 60
		if step < 60 {
			step = 60
		}
	}
	result := Series{StepSeconds: step, Points: []Point{}}
	rows, err := s.db.QueryContext(ctx, `SELECT (bucket/?)*?,sum(upload),sum(download),sum(connections),sum(observed_ms),max(gap) FROM traffic_minute WHERE network='all' AND target='' AND bucket>=? AND bucket<=? GROUP BY (bucket/?)*? ORDER BY bucket`, step, step, start, end, step, step)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		var point Point
		if err = rows.Scan(&point.Bucket, &point.Upload, &point.Download, &point.Connections, &point.ObservedMS, &point.Gap); err != nil {
			return result, err
		}
		result.Points = append(result.Points, point)
	}
	return result, rows.Err()
}

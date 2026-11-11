package traffic

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func trafficFixture(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBatchReplayDirectionAndRetentionBoundary(t *testing.T) {
	s := trafficFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	cutoff := now.Add(-Retention)
	batch := Batch{Instance: "fixture-instance", Sequence: 1, Rows: []Delta{
		{Bucket: now.Unix(), Network: "all", Upload: 123, Download: 456, Connections: 1},
		{Bucket: now.Unix(), Network: "tcp", Target: "198.51.100.1:443", Upload: 123, Download: 456, Connections: 1},
		{Bucket: cutoff.Unix(), Network: "all", Upload: 7, Download: 9},
		{Bucket: cutoff.Add(-time.Minute).Unix(), Network: "all", Upload: 10000, Download: 10000},
	}}
	if err := s.Append(ctx, batch, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, batch, now); err != nil {
		t.Fatal(err)
	}
	totals, err := s.Summary(ctx, now.Add(-365*24*time.Hour), now, now)
	if err != nil || totals.Upload != 130 || totals.Download != 465 || totals.Connections != 1 || totals.Gap {
		t.Fatal("traffic replay/direction/retention incorrect", totals, err)
	}
	// 绕过写入层植入超期哨兵，证明查询保护不能依赖后台清理恰好运行。
	if _, err = s.db.ExecContext(ctx, `INSERT INTO traffic_minute VALUES(?,'all','',100000,100000,0,0,0)`, cutoff.Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	totals, err = s.Summary(ctx, time.Unix(0, 0), now, now)
	if err != nil || totals.Upload != 130 {
		t.Fatal("query exposed traffic older than 30 days", totals, err)
	}
	if err = s.Purge(ctx, now); err != nil {
		t.Fatal(err)
	}
	var expired int
	if err = s.db.QueryRowContext(ctx, "SELECT count(*) FROM traffic_minute WHERE bucket<?", cutoff.Unix()).Scan(&expired); err != nil || expired != 0 {
		t.Fatal("purge retained expired traffic rows", expired, err)
	}
}

func TestSequenceGapMalformedBatchAndAtomicity(t *testing.T) {
	s := trafficFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	batch := Batch{Instance: "fixture-instance", Sequence: 2, Rows: []Delta{{Bucket: now.Unix(), Network: "all", Upload: 10}}}
	if err := s.Append(ctx, batch, now); err != nil {
		t.Fatal(err)
	}
	totals, err := s.Summary(ctx, now.Add(-time.Hour), now, now)
	if err != nil || !totals.Gap {
		t.Fatal("missing sequence was silently accepted", totals, err)
	}
	for _, bad := range []Batch{
		{Instance: "bad", Sequence: 3},
		{Instance: batch.Instance, Sequence: 0},
		{Instance: batch.Instance, Sequence: 3, Rows: []Delta{{Bucket: now.Add(2 * time.Minute).Unix(), Network: "all", Upload: 99}}},
		{Instance: batch.Instance, Sequence: 3, Rows: []Delta{{Bucket: now.Unix(), Network: "all", Upload: -1}}},
		{Instance: batch.Instance, Sequence: 3, Rows: []Delta{{Bucket: now.Unix(), Network: "all", Upload: 99}, {Bucket: now.Unix(), Network: "tcp", Target: "example.com:443", Upload: 99}}},
		{Instance: batch.Instance, Sequence: 3, Rows: []Delta{{Bucket: now.Unix(), Network: "tcp", Target: "198.51.100.1:443", Upload: 99}}},
	} {
		if err = s.Append(ctx, bad, now); err == nil {
			t.Fatal("bad traffic batch accepted", bad)
		}
	}
	totals, err = s.Summary(ctx, now.Add(-time.Hour), now, now)
	if err != nil || totals.Upload != 10 {
		t.Fatal("invalid batch partially changed traffic data", totals, err)
	}
	// 乱序旧批次不得补写并造成重复计量。
	batch.Sequence = 1
	batch.Rows[0].Upload = 10000
	if err = s.Append(ctx, batch, now); err != nil {
		t.Fatal(err)
	}
	totals, err = s.Summary(ctx, now.Add(-time.Hour), now, now)
	if err != nil || totals.Upload != 10 {
		t.Fatal("out-of-order batch counted again", totals, err)
	}
}

func TestTargetsTimelineSamplingDurationAndQueryRetention(t *testing.T) {
	s := trafficFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	rows := []Delta{{Bucket: now.Unix(), Network: "all", Upload: 30, Download: 70, Connections: 2, ObservedMS: 2000},
		{Bucket: now.Unix(), Network: "tcp", Target: "198.51.100.1:443", Upload: 10, Download: 20, Connections: 1},
		{Bucket: now.Unix(), Network: "udp", Target: "198.51.100.1:53", Upload: 5, Download: 15},
		{Bucket: now.Unix(), Network: "tcp", Target: "[2001:db8::1]:443", Upload: 15, Download: 35, Connections: 1}}
	if err := s.Append(ctx, Batch{Instance: "fixture-instance", Sequence: 1, Rows: rows}, now); err != nil {
		t.Fatal(err)
	}
	targets, err := s.Targets(ctx, time.Unix(0, 0), now, now, 100, 0)
	if err != nil || len(targets) != 2 {
		t.Fatal("target summary unavailable", targets, err)
	}
	for _, target := range targets {
		if target.IP == "198.51.100.1" && (target.Upload != 15 || target.Download != 35) {
			t.Fatal("same IP ports were not aggregated", target)
		}
	}
	series, err := s.Timeline(ctx, now.Add(-time.Hour), now, now)
	if err != nil || len(series.Points) != 1 || series.Points[0].ObservedMS != 2000 || series.Points[0].Upload != 30 {
		t.Fatal("timeline lost sampling duration or fabricated zero points", series, err)
	}
	old := now.Add(-Retention - time.Minute).Unix()
	if _, err = s.db.ExecContext(ctx, `INSERT INTO traffic_minute VALUES(?,'tcp','203.0.113.99:443',10000,10000,1,0,0)`, old); err != nil {
		t.Fatal(err)
	}
	targets, err = s.Targets(ctx, time.Unix(0, 0), now, now, 100, 0)
	if err != nil || len(targets) != 2 {
		t.Fatal("target query exposed IP beyond retention", targets, err)
	}
	if _, err = s.Targets(ctx, now, now, now, 100000, 0); err == nil {
		t.Fatal("unbounded target query accepted")
	}
}

func TestStatisticsFailureRemainsInIndependentDatabase(t *testing.T) {
	s := trafficFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	if _, err := Open(ctx, filepath.Join(t.TempDir(), "control.db")); err == nil {
		t.Fatal("statistics accepted authentication database path")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, Batch{Instance: "fixture-instance", Sequence: 1, Rows: []Delta{{Bucket: now.Unix(), Network: "all"}}}, now); err == nil {
		t.Fatal("closed statistics database reported successful ingest")
	}
}

func TestClearDoesNotResurrectBufferedHistory(t *testing.T) {
	s := trafficFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	batch := Batch{Instance: "fixture-instance", Sequence: 1, Rows: []Delta{{Bucket: now.Unix(), Network: "all", Upload: 10}}}
	if err := s.Append(ctx, batch, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear(ctx, now); err != nil {
		t.Fatal(err)
	}
	batch.Sequence = 2
	batch.Rows[0].Upload = 1000
	if err := s.Append(ctx, batch, now); err != nil {
		t.Fatal(err)
	}
	totals, err := s.Summary(ctx, now.Add(-time.Hour), now, now)
	if err != nil || totals.Upload != 0 {
		t.Fatal("cleared history resurrected from buffered batch", totals, err)
	}
	now = now.Add(time.Minute)
	batch.Sequence = 3
	batch.Rows[0].Bucket = now.Unix()
	batch.Rows[0].Upload = 20
	if err = s.Append(ctx, batch, now); err != nil {
		t.Fatal(err)
	}
	totals, err = s.Summary(ctx, now.Add(-time.Hour), now, now)
	if err != nil || totals.Upload != 20 {
		t.Fatal("history did not resume after clear boundary", totals, err)
	}
}

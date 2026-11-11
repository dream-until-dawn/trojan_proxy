package traffic

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// 真实SQLite锁和页配额故障，验证失败事务不能推进采集游标或留下半批统计。
func TestCollectorSQLiteFailuresAreReplayable(t *testing.T) {
	for _, failure := range []string{"write-lock", "page-quota"} {
		t.Run(failure, func(t *testing.T) {
			store := trafficFixture(t)
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Minute)
			rows := []Delta{{Bucket: now.Unix(), Network: "all", Upload: 511, ObservedMS: 2000}}
			for port := 1; port <= 511; port++ {
				rows = append(rows, Delta{Bucket: now.Unix(), Network: "tcp", Target: fmt.Sprintf("198.51.100.20:%d", port), Upload: 1})
			}
			batch := Batch{Instance: "failure-fixture", Sequence: 1, Rows: rows}
			source := &fakeSource{window: Window{Instance: batch.Instance, Oldest: 1, Latest: 1, Batches: []Batch{batch}}}
			collector := NewCollector(store, source)
			collector.now = func() time.Time { return now }
			var release func()
			if failure == "write-lock" {
				other, err := Open(ctx, store.path)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if _, err = other.db.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
					t.Fatal(err)
				}
				release = func() {
					if _, err := other.db.ExecContext(ctx, "ROLLBACK"); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				var pages int
				if err := store.db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); err != nil {
					t.Fatal(err)
				}
				if _, err := store.db.ExecContext(ctx, fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
					t.Fatal(err)
				}
				release = func() {
					if _, err := store.db.ExecContext(ctx, "PRAGMA max_page_count=65536"); err != nil {
						t.Fatal(err)
					}
				}
			}
			started := time.Now()
			err := collector.Poll(ctx)
			release()
			if err == nil {
				t.Fatal("SQLite fault did not reject statistics write")
			}
			if failure == "page-quota" && !strings.Contains(strings.ToLower(err.Error()), "full") {
				t.Fatal("quota probe failed for unrelated reason", err)
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("statistics failure exceeded bounded write budget")
			}
			if collector.sequence != 0 || collector.State().Available {
				t.Fatal("failed write advanced cursor or retained live status")
			}
			var count int
			if err = store.db.QueryRowContext(ctx, "SELECT count(*) FROM traffic_minute").Scan(&count); err != nil || count != 0 {
				t.Fatal("failed batch left partial statistics", count, err)
			}
			if err = collector.Poll(ctx); err != nil {
				t.Fatal("collector did not recover after SQLite fault", err)
			}
			if err = collector.Poll(ctx); err != nil {
				t.Fatal(err)
			}
			totals, err := store.Summary(ctx, now.Add(-time.Hour), now, now)
			if err != nil || totals.Upload != 511 || collector.sequence != 1 {
				t.Fatal("recovered batch lost or duplicated traffic", totals, err)
			}
		})
	}
}

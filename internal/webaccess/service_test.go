package webaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFullCollectorPrunesBeforeRetry(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "access.db")
	db, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	now := time.Now()
	old := make([]Record, 128)
	positions := make([]int64, 128)
	for i := range old {
		old[i] = testRecord("192.0.2.1", now.Add(-31*24*time.Hour))
		old[i].Path = "/" + strings.Repeat("x", 1900)
		positions[i] = int64(i)
	}
	if e = db.Ingest(ctx, "expired", 0, 128, 128, old, positions, 0, now); e != nil {
		t.Fatal(e)
	}
	var pages int64
	if e = db.db.QueryRow("PRAGMA page_count").Scan(&pages); e != nil {
		t.Fatal(e)
	}
	if _, e = db.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	line := fixtureLine(t, "/"+strings.Repeat("n", 1500))
	var value map[string]any
	json.Unmarshal(line, &value)
	value["ts"] = float64(now.Unix())
	line, _ = json.Marshal(value)
	line = append(line, '\n')
	if e = os.WriteFile(filepath.Join(dir, "requests.log"), []byte(strings.Repeat(string(line), 64)), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Collect(ctx, dir, now); e == nil {
		t.Fatal("夹具未触发采集写满")
	}
	service := NewService(path, dir)
	service.store = db
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); service.Run(bounded) }()
	for !service.State().Available && bounded.Err() == nil {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if !service.State().Available {
		t.Fatal("满库阻止到期清理与采集恢复", service.State())
	}
	reopened, e := Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	d, e := reopened.Dashboard(ctx, Filter{Hours: 24}, time.Now())
	if e != nil || d.Totals.Requests != 64 {
		t.Fatal("满库恢复丢失或重复", d, e)
	}
}

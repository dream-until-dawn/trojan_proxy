package traffic

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSource struct {
	window Window
	fail   bool
}

func (s *fakeSource) Fetch(context.Context, string, int64) (Window, error) {
	if s.fail {
		return Window{}, errors.New("fixture source unavailable")
	}
	return s.window, nil
}

func TestCollectorRatesRestartGapAndFailureIsolation(t *testing.T) {
	store := trafficFixture(t)
	now := time.Now().UTC().Truncate(time.Minute)
	ctx := context.Background()
	batch := Batch{Instance: "fixture-instance", Sequence: 1, Rows: []Delta{{Bucket: now.Unix(), Network: "all", Upload: 100, Download: 200, ObservedMS: 2000}}}
	source := &fakeSource{window: Window{Instance: batch.Instance, Oldest: 1, Latest: 1, Batches: []Batch{batch}}}
	collector := NewCollector(store, source)
	collector.now = func() time.Time { return now }
	if err := collector.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	state := collector.State()
	if !state.Available || state.UploadBPS != 50 || state.DownloadBPS != 100 {
		t.Fatal("live rate ignored actual sample duration", state)
	}
	if err := collector.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	totals, err := store.Summary(ctx, now.Add(-time.Hour), now, now)
	if err != nil || totals.Upload != 100 {
		t.Fatal("collector replay counted traffic again", totals, err)
	}
	source.fail = true
	if collector.Poll(ctx) == nil || collector.State().Available {
		t.Fatal("failed collector retained apparently live rate")
	}
	source.fail = false
	batch.Instance = "second-instance"
	source.window = Window{Instance: batch.Instance, Oldest: 1, Latest: 1, Batches: []Batch{batch}}
	if err = collector.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	totals, err = store.Summary(ctx, now.Add(-time.Hour), now, now)
	if err != nil || totals.Upload != 200 || !totals.Gap {
		t.Fatal("engine restart lost gap marker", totals, err)
	}
	now = now.Add(7 * time.Second)
	if collector.State().Available {
		t.Fatal("stale rate remained live")
	}
	if _, err = collector.Dashboard(ctx, 10000, 0); err == nil {
		t.Fatal("unbounded dashboard range accepted")
	}
	instance, sequence, err := store.Cursor(ctx)
	if err != nil || instance == "" || sequence != 1 {
		t.Fatal("collector progress not durable", instance, sequence, err)
	}
}

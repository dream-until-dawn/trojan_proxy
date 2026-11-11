// SPDX-License-Identifier: GPL-3.0-or-later
package telemetry

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

func samplerFixture(t *testing.T, targets, history int) (*Sampler, *time.Time) {
	t.Helper()
	s, err := NewSampler(targets, history)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000059, 500000000)
	s.last = now
	s.now = func() time.Time { return now }
	return s, &now
}

func TestSamplerCrossMinuteDurationAndExactGlobalTotals(t *testing.T) {
	s, now := samplerFixture(t, 256, 60)
	s.Record(Event{Network: "tcp", Target: netip.MustParseAddrPort("198.51.100.1:443"), Upload: 5, Download: 7, Connections: 1})
	*now = now.Add(time.Second)
	s.Record(Event{Network: "udp", Target: netip.MustParseAddrPort("[2001:db8::1]:53"), Upload: 3, Download: 2})
	*now = now.Add(time.Second)
	s.Flush()
	window := s.Snapshot("", 0)
	if len(window.Batches) != 1 {
		t.Fatal("sampler did not produce a batch")
	}
	var up, down, observed int64
	minutes := map[int64]int64{}
	for _, row := range window.Batches[0].Rows {
		if row.Network == "all" {
			up += row.Upload
			down += row.Download
			observed += row.ObservedMS
			minutes[row.Bucket] = row.ObservedMS
		}
	}
	if up != 8 || down != 9 || observed != 2000 || len(minutes) != 2 {
		t.Fatal("cross-minute sample totals incorrect", up, down, observed, minutes)
	}
	if minutes[1800000000] != 500 || minutes[1800000060] != 1500 {
		t.Fatal("sampling duration crossed minute incorrectly", minutes)
	}
}

func TestSamplerBoundsKeepGlobalAndMarkGaps(t *testing.T) {
	s, now := samplerFixture(t, 1, 2)
	for _, target := range []string{"198.51.100.1:443", "198.51.100.2:443"} {
		s.Record(Event{Network: "tcp", Target: netip.MustParseAddrPort(target), Upload: 10})
	}
	*now = now.Add(time.Second)
	s.Flush()
	window := s.Snapshot("", 0)
	var global Delta
	details := 0
	for _, row := range window.Batches[0].Rows {
		if row.Network == "all" {
			global.Upload += row.Upload
			global.Download += row.Download
			global.Gap = global.Gap || row.Gap
		} else {
			details++
		}
	}
	if global.Upload != 20 || !global.Gap || details != 1 {
		t.Fatal("bounded detail loss corrupted global totals", global, details)
	}
	for range 3 {
		*now = now.Add(time.Second)
		s.Flush()
	}
	window = s.Snapshot("", 0)
	if window.Oldest != 3 || window.Latest != 4 || len(window.Batches) != 2 {
		t.Fatal("sampler history exceeded budget", window)
	}
	*now = now.Add(-time.Hour)
	s.Flush()
	window = s.Snapshot(window.Instance, 4)
	if len(window.Batches) != 1 || !window.Batches[0].Rows[0].Gap {
		t.Fatal("backward clock was hidden", window)
	}
}

func TestSamplerConcurrentCounters(t *testing.T) {
	s, now := samplerFixture(t, 256, 60)
	var workers sync.WaitGroup
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 100 {
				s.Record(Event{Network: "tcp", Target: netip.MustParseAddrPort("198.51.100.1:443"), Upload: 1, Download: 2})
			}
		}()
	}
	workers.Wait()
	*now = now.Add(time.Second)
	s.Flush()
	window := s.Snapshot("", 0)
	var up, down int64
	for _, row := range window.Batches[0].Rows {
		if row.Network == "all" {
			up += row.Upload
			down += row.Download
		}
	}
	if up != 1600 || down != 3200 {
		t.Fatal("concurrent sampler counts lost", up, down)
	}
}

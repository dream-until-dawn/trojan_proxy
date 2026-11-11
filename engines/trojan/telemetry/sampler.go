// SPDX-License-Identifier: GPL-3.0-or-later
package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Delta 与控制面独立统计库的受限传输契约一致，不包含业务内容。
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
type Batch struct {
	Instance string  `json:"instance"`
	Sequence int64   `json:"sequence"`
	Rows     []Delta `json:"rows"`
}
type Window struct {
	Instance string  `json:"instance"`
	Oldest   int64   `json:"oldest"`
	Latest   int64   `json:"latest"`
	Batches  []Batch `json:"batches"`
}

// Sampler 只在内存维护固定上限的目标和批次；Record绝不写盘或等待采集客户端。
type Sampler struct {
	mu                     sync.Mutex
	instance               string
	sequence               int64
	rows                   map[string]Delta
	targets                int
	maxTargets, maxHistory int
	history                []Batch
	last                   time.Time
	now                    func() time.Time
}

// NewSampler 限制每轮最多256个目的明细和60个批次，默认调用者每2秒Flush。
func NewSampler(maxTargets, maxHistory int) (*Sampler, error) {
	if maxTargets < 1 || maxTargets > 256 || maxHistory < 1 || maxHistory > 60 {
		return nil, errors.New("统计内存预算无效")
	}
	var identity [16]byte
	if _, err := rand.Read(identity[:]); err != nil {
		return nil, err
	}
	return &Sampler{instance: hex.EncodeToString(identity[:]), rows: map[string]Delta{}, maxTargets: maxTargets, maxHistory: maxHistory, last: time.Now(), now: time.Now}, nil
}

func rowKey(bucket int64, network, target string) string {
	return fmt.Sprintf("%d/%s/%s", bucket, network, target)
}

func (s *Sampler) global(bucket int64) Delta {
	key := rowKey(bucket, "all", "")
	row, ok := s.rows[key]
	if !ok {
		// 时钟异常反复跳动时最多保留四个分钟，删除旧桶并明确标记缺口。
		count := 0
		oldest := int64(1<<63 - 1)
		for _, item := range s.rows {
			if item.Network == "all" {
				count++
				if item.Bucket < oldest {
					oldest = item.Bucket
				}
			}
		}
		gap := false
		if count >= 4 {
			for key, item := range s.rows {
				if item.Bucket == oldest {
					if item.Network != "all" {
						s.targets--
					}
					delete(s.rows, key)
				}
			}
			gap = true
		}
		row = Delta{Bucket: bucket, Network: "all", Gap: gap}
	}
	return row
}

// Record 在实际I/O返回后累计；达到明细上限仍保留全局计数并标出缺失。
func (s *Sampler) Record(event Event) {
	now := s.now()
	bucket := now.Unix() / 60 * 60
	s.mu.Lock()
	defer s.mu.Unlock()
	global := s.global(bucket)
	if event.Upload < 0 || event.Download < 0 || event.Connections < 0 {
		global.Gap = true
		s.rows[rowKey(bucket, "all", "")] = global
		return
	}
	global.Upload += event.Upload
	global.Download += event.Download
	global.Connections += event.Connections
	valid := event.Target.IsValid() && event.Target.Port() != 0 && (event.Network == "tcp" || event.Network == "udp")
	key := rowKey(bucket, event.Network, event.Target.String())
	detail, exists := s.rows[key]
	if !valid || (!exists && s.targets >= s.maxTargets) {
		global.Gap = true
	} else {
		if !exists {
			detail = Delta{Bucket: bucket, Network: event.Network, Target: event.Target.String()}
			s.targets++
		}
		detail.Upload += event.Upload
		detail.Download += event.Download
		detail.Connections += event.Connections
		s.rows[key] = detail
	}
	s.rows[rowKey(bucket, "all", "")] = global
}

// Flush 切分跨分钟的实际观察时长，时钟漂移/长暂停不伪装成连续零流量。
func (s *Sampler) Flush() {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	wall := now.UnixMilli() - s.last.UnixMilli()
	elapsed := now.Sub(s.last).Milliseconds()
	difference := wall - elapsed
	clockOK := wall >= 0 && wall <= 5000 && difference >= -1000 && difference <= 1000
	if clockOK {
		for start := s.last.UnixMilli(); start < now.UnixMilli(); {
			bucket := start / 60000 * 60
			end := (bucket + 60) * 1000
			if end > now.UnixMilli() {
				end = now.UnixMilli()
			}
			global := s.global(bucket)
			global.ObservedMS += end - start
			s.rows[rowKey(bucket, "all", "")] = global
			start = end
		}
	} else {
		global := s.global(now.Unix() / 60 * 60)
		global.Gap = true
		s.rows[rowKey(global.Bucket, "all", "")] = global
		for key, row := range s.rows {
			row.Gap = true
			s.rows[key] = row
		}
	}
	if len(s.rows) == 0 {
		bucket := now.Unix() / 60 * 60
		s.rows[rowKey(bucket, "all", "")] = Delta{Bucket: bucket, Network: "all"}
	}
	rows := make([]Delta, 0, len(s.rows))
	for _, row := range s.rows {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Bucket != rows[j].Bucket {
			return rows[i].Bucket < rows[j].Bucket
		}
		if rows[i].Network != rows[j].Network {
			return rows[i].Network < rows[j].Network
		}
		return rows[i].Target < rows[j].Target
	})
	s.sequence++
	s.history = append(s.history, Batch{Instance: s.instance, Sequence: s.sequence, Rows: rows})
	if len(s.history) > s.maxHistory {
		drop := len(s.history) - s.maxHistory
		for index := 0; index < drop; index++ {
			s.history[index] = Batch{}
		}
		s.history = s.history[drop:]
	}
	s.rows = map[string]Delta{}
	s.targets = 0
	s.last = now
}

// Snapshot 返回最多四批副本，JSON编码在锁外完成；实例变化时从当前最早批次开始。
func (s *Sampler) Snapshot(instance string, after int64) Window {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := Window{Instance: s.instance, Latest: s.sequence, Batches: []Batch{}}
	if len(s.history) > 0 {
		result.Oldest = s.history[0].Sequence
	}
	if instance != s.instance {
		after = 0
	}
	for _, batch := range s.history {
		if batch.Sequence > after {
			batch.Rows = append([]Delta(nil), batch.Rows...)
			result.Batches = append(result.Batches, batch)
			if len(result.Batches) >= 4 {
				break
			}
		}
	}
	return result
}

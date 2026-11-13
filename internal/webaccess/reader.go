package webaccess

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Collect 从只读专用目录读取完整行，事务成功后才推进持久游标。
func (s *Store) Collect(ctx context.Context, directory string, now time.Time) (int64, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return 0, err
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return 0, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var backlog int64
	var failures []error
	for _, entry := range entries {
		name := entry.Name()
		if name != "requests.log" && !(strings.HasPrefix(name, "requests-") && strings.HasSuffix(name, ".log")) {
			continue
		}
		f, err := root.Open(name)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		remaining, err := s.collectFile(ctx, f, now)
		f.Close()
		backlog += remaining
		if err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) == 0 {
		if err = s.NoteCollection(ctx, now); err != nil {
			failures = append(failures, err)
		}
	}
	return backlog, errors.Join(failures...)
}
func (s *Store) collectFile(ctx context.Context, f *os.File, now time.Time) (int64, error) {
	info, err := f.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, errors.New("访问来源不是普通文件")
	}
	if info.Size() == 0 {
		return 0, nil
	}
	reader := bufio.NewReaderSize(f, 65536)
	first, err := reader.ReadSlice('\n')
	if err == io.EOF {
		return info.Size(), nil
	}
	if err != nil {
		return info.Size(), errors.New("访问文件首行无效")
	}
	identity, err := fileIdentity(f)
	if err != nil {
		return 0, err
	}
	hash := sha256.Sum256(first)
	source := identity + ":" + hex.EncodeToString(hash[:])
	cursor, err := s.Cursor(ctx, source)
	if err != nil {
		return 0, err
	}
	if cursor.Offset > info.Size() {
		if err = s.Truncated(ctx, source); err != nil {
			return 0, err
		}
		cursor.Offset = 0
	}
	if _, err = f.Seek(cursor.Offset, io.SeekStart); err != nil {
		return 0, err
	}
	// 固定本轮快照大小，避免写入方追加时读过size、造成游标事务被拒绝。
	reader.Reset(io.LimitReader(f, info.Size()-cursor.Offset))
	end := cursor.Offset
	records := []Record{}
	positions := []int64{}
	invalid := 0
	for count := 0; count < 256; count++ {
		line, err := reader.ReadSlice('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return info.Size() - end, errors.New("访问日志行超过预算或读取失败")
		}
		position := end
		end += int64(len(line))
		record, err := Parse(line, now)
		if err != nil {
			invalid++
			continue
		}
		records = append(records, record)
		positions = append(positions, position)
	}
	if err = s.Ingest(ctx, source, cursor.Offset, end, info.Size(), records, positions, invalid, now); err != nil {
		return info.Size() - cursor.Offset, err
	}
	return info.Size() - end, nil
}

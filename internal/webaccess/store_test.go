package webaccess

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 13, 3, 0, 0, 0, time.UTC)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, e := Open(context.Background(), filepath.Join(t.TempDir(), "access.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func testRecord(ip string, at time.Time) Record {
	return Record{At: at.UnixMilli(), IP: ip, Host: "example.test", Port: 443, Method: "GET", Path: "/flow", Status: 200, DurationMS: 1, Upload: 2, Download: 3}
}
func insert(t *testing.T, s *Store, rs ...Record) {
	t.Helper()
	ps := make([]int64, len(rs))
	for i := range ps {
		ps[i] = int64(i)
	}
	if e := s.Ingest(context.Background(), "fixture", 0, int64(len(rs)), int64(len(rs)), rs, ps, 0, testNow); e != nil {
		t.Fatal(e)
	}
}
func dashboard(t *testing.T, s *Store) Dashboard {
	t.Helper()
	d, e := s.Dashboard(context.Background(), Filter{Hours: 720}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	return d
}

func TestRetentionCurrentWhitelistAndExactBoundaries(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	insert(t, s, testRecord("192.0.2.1", testNow.Add(-7*24*time.Hour)), testRecord("192.0.2.1", testNow.Add(-7*24*time.Hour+time.Millisecond)), testRecord("198.51.100.1", testNow.Add(-30*24*time.Hour)), testRecord("198.51.100.1", testNow.Add(-30*24*time.Hour+time.Millisecond)))
	if d := dashboard(t, s); d.Totals.Requests != 3 {
		t.Fatal("30天查询边界失效", d)
	}
	if e := s.SetWhitelist(ctx, 1, []string{"192.0.2.0/24"}, testNow); e != nil {
		t.Fatal(e)
	}
	d := dashboard(t, s)
	if d.Totals.Requests != 2 || d.Totals.Trusted != 1 {
		t.Fatal("历史未按当前名单重分类或7天边界失效", d)
	}
	var n int
	if e := s.db.QueryRow("SELECT count(*) FROM requests").Scan(&n); e != nil || n != 2 {
		t.Fatal("到期记录未物理删除", n, e)
	}
	if e := s.SetWhitelist(ctx, 1, nil, testNow); !errors.Is(e, ErrRevision) {
		t.Fatal("过时修订覆盖了策略", e)
	}
	if e := s.SetWhitelist(ctx, 2, nil, testNow); e != nil {
		t.Fatal(e)
	}
	if d = dashboard(t, s); d.Totals.Requests != 2 || d.Totals.Trusted != 0 {
		t.Fatal("移出名单未重分类或已删除历史被恢复", d)
	}
	// 查询TTL独立于清理：绕过清理直接推进查询时钟。
	d, e := s.Dashboard(ctx, Filter{Hours: 720}, testNow.Add(31*24*time.Hour))
	if e != nil || d.Totals.Requests != 0 {
		t.Fatal("清理延迟泄露到期数据", e, d)
	}
}
func TestIPv4IPv6RangesAndMappedAddress(t *testing.T) {
	s := testStore(t)
	insert(t, s, testRecord("::ffff:192.0.2.8", testNow), testRecord("192.0.3.1", testNow), testRecord("2001:db8::1", testNow), testRecord("2001:db9::1", testNow))
	for _, tc := range []struct {
		list []string
		want int64
	}{{[]string{"::/0"}, 2}, {[]string{"::ffff:192.0.2.99/120", "2001:db8::/32"}, 2}, {[]string{"0.0.0.0/0"}, 2}} {
		p, _ := s.Policy(context.Background())
		if e := s.SetWhitelist(context.Background(), p.Revision, tc.list, testNow); e != nil {
			t.Fatal(e)
		}
		if d := dashboard(t, s); d.Totals.Trusted != tc.want {
			t.Fatal("IP族或CIDR范围错误", tc, d)
		}
	}
	for _, bad := range []string{"example.com", "192.0.2.1/33", "fe80::1%eth0", "::ffff:192.0.2.1/80", "1.2.3.4;DROP TABLE"} {
		if _, e := NormalizeWhitelist([]string{bad}); e == nil {
			t.Fatal("无效白名单未拒绝", bad)
		}
	}
}

func TestTrustedQueryTTLIndependentOfPruning(t *testing.T) {
	s := testStore(t)
	insert(t, s, testRecord("192.0.2.1", testNow.Add(-8*24*time.Hour)))
	// 模拟策略已经更新、物理清理尚未运行，查询仍必须执行7天TTL。
	if _, e := s.db.Exec(`UPDATE policy SET revision=2,cidrs='["192.0.2.1/32"]'`); e != nil {
		t.Fatal(e)
	}
	if d := dashboard(t, s); d.Totals.Requests != 0 {
		t.Fatal("trusted query exposed expired history", d)
	}
}

func TestStoreFullRollsBackCursorAndRecovers(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var count int64
	if e := s.db.QueryRow("PRAGMA page_count").Scan(&count); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", count+4)); e != nil {
		t.Fatal(e)
	}
	rs := make([]Record, 128)
	positions := make([]int64, 128)
	for i := range rs {
		rs[i] = testRecord("192.0.2.1", testNow)
		rs[i].Path = "/" + strings.Repeat("x", 1900)
		positions[i] = int64(i)
	}
	if e := s.Ingest(ctx, "full", 0, 128, 128, rs, positions, 0, testNow); e == nil {
		t.Fatal("受限访问库未触发真实SQLite FULL")
	}
	c, e := s.Cursor(ctx, "full")
	if e != nil || c.Offset != 0 || dashboard(t, s).Totals.Requests != 0 {
		t.Fatal("写满发生部分写入或游标提前推进", c, e)
	}
	if _, e = s.db.Exec("PRAGMA max_page_count=262144"); e != nil {
		t.Fatal(e)
	}
	if e = s.Ingest(ctx, "full", 0, 128, 128, rs, positions, 0, testNow); e != nil {
		t.Fatal("容量恢复后无法原批次补采", e)
	}
	if d := dashboard(t, s); d.Totals.Requests != 128 {
		t.Fatal("容量恢复后漏记或重复", d)
	}
}
func fixtureLine(t *testing.T, path string) []byte {
	t.Helper()
	v := map[string]any{"ts": float64(testNow.Unix()), "logger": "http.log.access.web_access.p443", "status": 200, "duration": 0.01, "size": 3, "bytes_read": 2, "request": map[string]any{"remote_ip": "192.0.2.1", "client_ip": "198.51.100.99", "host": "EXAMPLE.test:443", "method": "GET", "uri": path, "headers": map[string]string{"Authorization": "secret"}}}
	b, _ := json.Marshal(v)
	return append(b, '\n')
}
func TestParserPrivacyAndHostileInput(t *testing.T) {
	for _, path := range []string{"/flow/a?token=secret", "https://user:secret@example.test/flow/a?token=secret"} {
		r, e := Parse(fixtureLine(t, path), testNow)
		if e != nil || r.IP != "192.0.2.1" || r.Path != "/flow/a" || r.Host != "example.test" || r.Port != 443 {
			t.Fatal("隐私字段或真实来源错误", r, e)
		}
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "secret") || strings.Contains(string(b), "198.51.100.99") {
			t.Fatal("秘密进入记录", string(b))
		}
	}
	for _, line := range [][]byte{[]byte(`{`), []byte(strings.Repeat("a", 65537)), []byte(strings.ReplaceAll(string(fixtureLine(t, "/")), "web_access.p443", "traffic.p443")), []byte(strings.ReplaceAll(string(fixtureLine(t, "/")), "192.0.2.1", "invalid"))} {
		if _, e := Parse(line, testNow); e == nil {
			t.Fatal("畸形记录未拒绝")
		}
	}
}
func TestCollectorRotationRestartPartialAndReplay(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	dir := t.TempDir()
	active := filepath.Join(dir, "requests.log")
	line := fixtureLine(t, "/first")
	partial := fixtureLine(t, "/second")
	if e := os.WriteFile(active, append(append([]byte{}, line...), partial[:len(partial)-1]...), 0600); e != nil {
		t.Fatal(e)
	}
	if backlog, e := s.Collect(ctx, dir, testNow); e != nil || backlog == 0 {
		t.Fatal("半行处理错误", backlog, e)
	}
	if d := dashboard(t, s); d.Totals.Requests != 1 {
		t.Fatal(d)
	}
	// 重开数据库验证游标持久化，未完成行在重启后补齐一次。
	var path string
	s.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path)
	s.Close()
	var e error
	s, e = Open(ctx, path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	f, _ := os.OpenFile(active, os.O_APPEND|os.O_WRONLY, 0600)
	f.Write([]byte{'\n'})
	f.Close()
	if e = os.Rename(active, filepath.Join(dir, "requests-2026-11-13.log")); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(active, fixtureLine(t, "/third"), 0600)
	for i := 0; i < 2; i++ {
		if _, e = s.Collect(ctx, dir, testNow); e != nil {
			t.Fatal(e)
		}
	}
	if d := dashboard(t, s); d.Totals.Requests != 3 {
		t.Fatal("轮转或重启丢失/重复请求", d)
	}
	if _, e = s.Collect(ctx, filepath.Join(dir, "missing"), testNow); e == nil {
		t.Fatal("日志不可用被伪装为成功")
	}
}
func TestPaginationFiltersAndAtomicInvalidBatch(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	rs := make([]Record, 55)
	for i := range rs {
		rs[i] = testRecord("192.0.2.1", testNow)
	}
	rs[0].Status = 502
	insert(t, s, rs...)
	d := dashboard(t, s)
	if len(d.Rows) != 50 || d.Next == 0 || d.Totals.Errors != 1 {
		t.Fatal(d)
	}
	next, e := s.Dashboard(ctx, Filter{Hours: 24, Before: d.Next}, testNow)
	if e != nil || len(next.Rows) != 5 {
		t.Fatal(next, e)
	}
	filtered, e := s.Dashboard(ctx, Filter{Hours: 24, Class: 5, Path: "/flo", IP: "::ffff:192.0.2.1"}, testNow)
	if e != nil || filtered.Totals.Requests != 1 {
		t.Fatal(filtered, e)
	}
	bad := testRecord("192.0.2.1", testNow)
	bad.Path = "/?password=secret"
	if e = s.Ingest(ctx, "bad", 0, 2, 2, []Record{rs[0], bad}, []int64{0, 1}, 0, testNow); e == nil {
		t.Fatal("非法记录批次未拒绝")
	}
	c, _ := s.Cursor(ctx, "bad")
	if c.Offset != 0 || dashboard(t, s).Totals.Requests != 55 {
		t.Fatal("非法批次发生部分提交")
	}
	if e = s.Ingest(ctx, "fixture", 0, 55, 55, rs, make([]int64, 55), 0, testNow); e == nil {
		t.Fatal("非递增偏移未拒绝")
	}
	if e = s.db.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Dashboard(ctx, Filter{Hours: 24}, testNow); e == nil {
		t.Fatal("存储故障被伪装为零请求")
	}
}

package webaccess

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"
)

func ValidateFilter(f Filter) error {
	if f.Hours < 1 || f.Hours > 720 || f.Before < 0 || f.Class < 0 || f.Class > 5 || len(f.Host) > 512 || len(f.Path) > 2048 {
		return errors.New("访问筛选范围无效")
	}
	if f.Trust != "" && f.Trust != "all" && f.Trust != "trusted" && f.Trust != "other" {
		return errors.New("访问来源分类无效")
	}
	if f.IP != "" {
		if _, err := netip.ParseAddr(f.IP); err != nil {
			return errors.New("筛选IP无效")
		}
	}
	return nil
}

// Dashboard 的可见窗口在查询时强制执行，清理协程延迟也不会多展示过期记录。
func (s *Store) Dashboard(ctx context.Context, f Filter, now time.Time) (Dashboard, error) {
	d := Dashboard{Rows: []Record{}, Hourly: []Bucket{}}
	if err := ValidateFilter(f); err != nil {
		return d, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return d, err
	}
	defer tx.Rollback()
	p, err := readPolicy(ctx, tx)
	if err != nil {
		return d, err
	}
	trusted, args := whitelistSQL(p.CIDRs)
	cte := "WITH classified AS (SELECT *, " + trusted + " AS trusted FROM requests WHERE at>? AND at<=?) "
	args = append(args, now.Add(-time.Duration(f.Hours)*time.Hour).UnixMilli(), now.UnixMilli())
	where := " WHERE (trusted=0 OR at>?)"
	args = append(args, now.Add(-TrustedRetention).UnixMilli())
	if f.IP != "" {
		ip, _ := netip.ParseAddr(f.IP)
		where += " AND ip=?"
		args = append(args, ip.Unmap().String())
	}
	if f.Host != "" {
		where += " AND host=?"
		args = append(args, strings.ToLower(f.Host))
	}
	if f.Path != "" {
		where += " AND substr(path,1,length(?))=?"
		args = append(args, f.Path, f.Path)
	}
	if f.Class != 0 {
		where += " AND status>=? AND status<?"
		args = append(args, f.Class*100, (f.Class+1)*100)
	}
	if f.Trust == "trusted" {
		where += " AND trusted=1"
	} else if f.Trust == "other" {
		where += " AND trusted=0"
	}
	err = tx.QueryRowContext(ctx, cte+`SELECT count(*),coalesce(sum(trusted),0),coalesce(sum(status>=400),0),coalesce(sum(upload),0),coalesce(sum(download),0) FROM classified`+where, args...).Scan(&d.Totals.Requests, &d.Totals.Trusted, &d.Totals.Errors, &d.Totals.Upload, &d.Totals.Download)
	if err != nil {
		return d, err
	}
	rows, err := tx.QueryContext(ctx, cte+`SELECT (at/3600000)*3600000,count(*),sum(status>=400) FROM classified`+where+` GROUP BY at/3600000 ORDER BY at/3600000 LIMIT 720`, args...)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var b Bucket
		if err = rows.Scan(&b.At, &b.Requests, &b.Errors); err != nil {
			rows.Close()
			return d, err
		}
		d.Hourly = append(d.Hourly, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, err
	}
	pageWhere := where
	pageArgs := append([]any(nil), args...)
	if f.Before > 0 {
		pageWhere += " AND id<?"
		pageArgs = append(pageArgs, f.Before)
	}
	rows, err = tx.QueryContext(ctx, cte+`SELECT id,at,ip,host,port,method,path,status,duration,upload,download,trusted FROM classified`+pageWhere+` ORDER BY id DESC LIMIT 51`, pageArgs...)
	if err != nil {
		return d, err
	}
	for rows.Next() {
		var r Record
		if err = rows.Scan(&r.ID, &r.At, &r.IP, &r.Host, &r.Port, &r.Method, &r.Path, &r.Status, &r.DurationMS, &r.Upload, &r.Download, &r.Trusted); err != nil {
			rows.Close()
			return d, err
		}
		d.Rows = append(d.Rows, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return d, err
	}
	if len(d.Rows) > 50 {
		d.Rows = d.Rows[:50]
		d.Next = d.Rows[49].ID
	}
	return d, tx.Commit()
}

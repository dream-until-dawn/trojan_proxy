// Package webaccess 仅保存网站HTTP访问元数据，不读写VPN流量或认证库。
package webaccess

import "time"

const TrustedRetention = 7 * 24 * time.Hour
const OtherRetention = 30 * 24 * time.Hour

// Record 一次已完成HTTP请求；没有查询、头、正文或VPN目标字段。
type Record struct {
	ID         int64   `json:"id"`
	At         int64   `json:"at_ms"`
	IP         string  `json:"ip"`
	Host       string  `json:"host"`
	Port       int     `json:"port"`
	Method     string  `json:"method"`
	Path       string  `json:"path"`
	Status     int     `json:"status"`
	DurationMS float64 `json:"duration_ms"`
	Upload     int64   `json:"upload"`
	Download   int64   `json:"download"`
	Trusted    bool    `json:"trusted"`
}

// Policy 使用独立修订防止过时页面覆盖白名单；名单不是防火墙。
type Policy struct {
	Revision uint64   `json:"revision"`
	CIDRs    []string `json:"cidrs"`
}
type Filter struct {
	Hours  int    `json:"hours"`
	IP     string `json:"ip"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Class  int    `json:"status_class"`
	Trust  string `json:"trust"`
	Before int64  `json:"before_id"`
}
type Totals struct {
	Requests int64 `json:"requests"`
	Trusted  int64 `json:"trusted"`
	Errors   int64 `json:"errors"`
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
}
type Bucket struct {
	At       int64 `json:"at_ms"`
	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`
}
type Dashboard struct {
	Totals Totals   `json:"totals"`
	Rows   []Record `json:"rows"`
	Hourly []Bucket `json:"hourly"`
	Next   int64    `json:"next_before_id"`
}
type Cursor struct {
	Offset     int64
	Size       int64
	Generation int64
}

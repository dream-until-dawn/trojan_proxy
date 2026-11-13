package webaccess

import (
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func limited(value string, max int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	if len(value) > max {
		return value[:max]
	}
	return value
}

func validateRecord(r Record, now time.Time) error {
	if r.At <= 0 || r.At > now.Add(time.Minute).UnixMilli() || len(r.Host) > 512 || r.Method == "" || len(r.Method) > 32 || len(r.Path) > 2048 || !(strings.HasPrefix(r.Path, "/") || r.Path == "*") || strings.ContainsAny(r.Path, "?#\x00\r\n") || r.Port < 1 || r.Port > 65535 || r.Status < 0 || (r.Status > 0 && r.Status < 100) || r.Status > 599 || math.IsNaN(r.DurationMS) || math.IsInf(r.DurationMS, 0) || r.DurationMS < 0 || r.DurationMS > float64(OtherRetention/time.Millisecond) || r.Upload < 0 || r.Download < 0 {
		return errors.New("访问记录字段无效")
	}
	return nil
}

// Parse 只接受专用logger；来源取remote_ip，绝不读取XFF/client_ip或头字段。
func Parse(line []byte, now time.Time) (Record, error) {
	var input struct {
		TS       float64 `json:"ts"`
		Logger   string  `json:"logger"`
		Status   int     `json:"status"`
		Duration float64 `json:"duration"`
		Read     int64   `json:"bytes_read"`
		Size     int64   `json:"size"`
		Request  struct {
			IP     string `json:"remote_ip"`
			Host   string `json:"host"`
			Method string `json:"method"`
			URI    string `json:"uri"`
		} `json:"request"`
	}
	var r Record
	if len(line) > 65536 {
		return r, errors.New("访问日志行超过预算")
	}
	if err := json.Unmarshal(line, &input); err != nil {
		return r, errors.New("访问日志格式无效")
	}
	const prefix = "http.log.access.web_access.p"
	if !strings.HasPrefix(input.Logger, prefix) {
		return r, errors.New("非网站访问日志")
	}
	port, err := strconv.Atoi(strings.TrimPrefix(input.Logger, prefix))
	if err != nil || port < 1 || port > 65535 {
		return r, errors.New("访问入口无效")
	}
	ip, err := netip.ParseAddr(input.Request.IP)
	if err != nil {
		return r, errors.New("连接来源IP无效")
	}
	ip = ip.Unmap().WithZone("")
	if math.IsNaN(input.TS) || math.IsInf(input.TS, 0) || input.TS <= 0 || input.TS > float64(now.Add(time.Minute).Unix()) || input.Duration < 0 || input.Duration > float64(OtherRetention/time.Second) || input.Read < 0 || input.Size < 0 || input.Status < 0 || input.Status > 599 {
		return r, errors.New("访问记录数值无效")
	}
	// 双重防护：即使导入误配置的旧日志，也不将查询或绝对URL用户信息写入数据库。
	uri, err := url.ParseRequestURI(input.Request.URI)
	path := "/"
	if err == nil {
		path = uri.EscapedPath()
		if path == "" && input.Request.URI == "*" {
			path = "*"
		}
	}
	if path == "" {
		path = "/"
	}
	host := input.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	r = Record{At: int64(input.TS * 1000), IP: ip.String(), Host: limited(host, 512), Port: port, Method: limited(input.Request.Method, 32), Path: limited(path, 2048), Status: input.Status, DurationMS: input.Duration * 1000, Upload: input.Read, Download: input.Size}
	if r.Method == "" {
		r.Method = "UNKNOWN"
	}
	return r, validateRecord(r, now)
}

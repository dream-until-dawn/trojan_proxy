package traffic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Window 只包含最多四个批次，采用进程实例和序号定位，不能调用引擎配置API。
type Window struct {
	Instance string  `json:"instance"`
	Oldest   int64   `json:"oldest"`
	Latest   int64   `json:"latest"`
	Batches  []Batch `json:"batches"`
}
type Source interface {
	Fetch(context.Context, string, int64) (Window, error)
}

// Client 的唯一目标由部署确定，不读取环境代理，不接受网页传入URL。
type Client struct{ http *http.Client }

func NewClient(socket string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	return &Client{http: &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) Fetch(ctx context.Context, instance string, after int64) (Window, error) {
	values := url.Values{"instance": {instance}, "after": {strconv.FormatInt(after, 10)}}
	request, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/snapshot?"+values.Encode(), nil)
	if err != nil {
		return Window{}, err
	}
	response, err := c.http.Do(request)
	if err != nil {
		return Window{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return Window{}, errors.New("统计执行器暂不可用")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 512*1024+1))
	if err != nil {
		return Window{}, err
	}
	if len(body) > 512*1024 {
		return Window{}, errors.New("统计快照超过预算")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var result Window
	if err = decoder.Decode(&result); err != nil {
		return Window{}, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Window{}, errors.New("统计快照包含尾随数据")
	}
	if !instancePattern.MatchString(result.Instance) || result.Latest < 0 || result.Oldest < 0 || result.Oldest > result.Latest || len(result.Batches) > 4 {
		return Window{}, errors.New("统计快照格式错误")
	}
	previous := int64(0)
	for _, batch := range result.Batches {
		if batch.Instance != result.Instance || batch.Sequence <= previous || batch.Sequence > result.Latest || len(batch.Rows) > 512 {
			return Window{}, errors.New("统计快照批次格式错误")
		}
		previous = batch.Sequence
	}
	return result, nil
}

// Live 表示最近一个有效采样窗口；缺数据与正常零流量明确区分。
type Live struct {
	Available   bool    `json:"available"`
	UploadBPS   float64 `json:"upload_bps"`
	DownloadBPS float64 `json:"download_bps"`
	SampleAt    int64   `json:"sample_at"`
	Gap         bool    `json:"gap"`
	Message     string  `json:"message"`
}

// Collector 异步采集到独立统计库，任何失败只影响此模块。
type Collector struct {
	pollMu   sync.Mutex
	mu       sync.Mutex
	store    *Store
	source   Source
	instance string
	sequence int64
	live     Live
	now      func() time.Time
}

func NewCollector(store *Store, source Source) *Collector {
	return &Collector{store: store, source: source, now: time.Now}
}

func (c *Collector) unavailable(message string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.live.Available = false
	c.live.Message = message
}

// Poll 一次只追赶有限批次；入库失败不推进游标，下一次仍可安全重放。
func (c *Collector) Poll(ctx context.Context) error {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	window, err := c.source.Fetch(ctx, c.instance, c.sequence)
	if err != nil {
		c.unavailable("当前没有可用采样，历史记录仍可查询")
		return err
	}
	changed := c.instance != "" && c.instance != window.Instance
	for _, batch := range window.Batches {
		if batch.Sequence <= c.sequence && batch.Instance == c.instance {
			continue
		}
		if changed {
			for index := range batch.Rows {
				if batch.Rows[index].Network == "all" {
					batch.Rows[index].Gap = true
				}
			}
		}
		if err = c.store.Append(ctx, batch, c.now()); err != nil {
			c.unavailable("统计写入失败，请检查磁盘、容量或数据库状态")
			return err
		}
		c.instance = batch.Instance
		c.sequence = batch.Sequence
		if batch.Sequence == window.Latest {
			var up, down, observed int64
			gap := false
			for _, row := range batch.Rows {
				if row.Network == "all" {
					up += row.Upload
					down += row.Download
					observed += row.ObservedMS
					gap = gap || row.Gap
				}
			}
			live := Live{Available: observed > 0, SampleAt: c.now().Unix(), Gap: gap, Message: "采样正常"}
			if observed > 0 {
				live.UploadBPS = float64(up) * 1000 / float64(observed)
				live.DownloadBPS = float64(down) * 1000 / float64(observed)
			} else {
				live.Message = "采样时钟异常或窗口尚未形成"
			}
			c.mu.Lock()
			c.live = live
			c.mu.Unlock()
		}
	}
	return nil
}

// State 不返回目的明细；超过6秒没有新窗口时不能继续显示旧网速为实时值。
func (c *Collector) State() Live {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := c.live
	if c.now().Unix()-result.SampleAt > 6 {
		result.Available = false
		result.Message = "没有最新采样窗口"
	}
	return result
}

// Run 以受限请求和清理预算运行，调用方须在关闭统计库之前等待退出。
func (c *Collector) Run(ctx context.Context) {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	purge := time.NewTicker(time.Hour)
	defer purge.Stop()
	clean := func() {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if c.store.Purge(bounded, c.now()) != nil {
			c.unavailable("统计清理未完成，历史查询仍限制为30天")
		}
	}
	clean()
	if instance, sequence, err := c.store.Cursor(ctx); err == nil {
		c.instance = instance
		c.sequence = sequence
	}
	for {
		bounded, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		c.Poll(bounded)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-purge.C:
			clean()
		}
	}
}

// Package gateway 通过受限Unix socket配置网关，不使用Docker socket或任意命令。
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"time"
)

// Client 封装固定网关管理socket。
type Client struct{ http *http.Client }

// NewClient 禁用环境代理，所有请求只能到指定Unix socket。
func NewClient(socket string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	return &Client{http: &http.Client{Transport: transport, Timeout: 10 * time.Second}}
}

// Check 先做无副作用的语法检查，完整模块校验由原子load执行。
func (c *Client) Check(_ context.Context, config string) error {
	if len(config) > 1024*1024 || !json.Valid([]byte(config)) {
		return errors.New("网关配置不是有效JSON或超出大小限制")
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(config), &root); err != nil {
		return err
	}
	if root["apps"] == nil {
		return errors.New("网关配置缺少应用")
	}
	return nil
}

func (c *Client) request(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	r, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(r)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1024*1024 {
		return nil, errors.New("网关响应过大")
	}
	if response.StatusCode >= 300 {
		return nil, fmt.Errorf("网关拒绝应用，HTTP %d", response.StatusCode)
	}
	return data, nil
}

// Apply 原子替换完整网关配置；失败时Caddy保留旧配置。
func (c *Client) Apply(ctx context.Context, config string) error {
	if err := c.Check(ctx, config); err != nil {
		return err
	}
	if _, err := c.request(ctx, "POST", "/load", []byte(config)); err != nil {
		return err
	}
	actual, err := c.Current(ctx)
	if err != nil {
		return err
	}
	var expectedValue, actualValue any
	if err = json.Unmarshal([]byte(config), &expectedValue); err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(actual), &actualValue); err != nil {
		return err
	}
	if !reflect.DeepEqual(expectedValue, actualValue) {
		return errors.New("网关实际配置与提交快照不一致")
	}
	return nil
}

// Current 读取网关实际完整配置，供初次修订快照和恢复核对使用。
func (c *Client) Current(ctx context.Context) (string, error) {
	b, err := c.request(ctx, "GET", "/config/", nil)
	return string(b), err
}

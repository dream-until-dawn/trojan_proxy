package vpnrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

// Handler 只能交给专用Unix监听器，部署不能把它绑定为TCP服务。
func (e *Engine) Handler() http.Handler {
	mux := http.NewServeMux()
	respond := func(w http.ResponseWriter, status int, value any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, e.Status()) })
	for _, operation := range []string{"check", "apply"} {
		mux.HandleFunc("POST /"+operation, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Content-Type") != "application/json" {
				respond(w, 415, map[string]string{"error": "执行器仅接受JSON"})
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
			if err != nil {
				respond(w, 400, map[string]string{"error": "执行器命令超出限制"})
				return
			}
			desired, err := vpn.DecodeCommand(body)
			if err != nil {
				respond(w, 400, map[string]string{"error": "执行器命令格式错误"})
				return
			}
			if operation == "check" {
				err = e.Check(r.Context(), desired)
			} else {
				err = e.Apply(r.Context(), desired)
			}
			if err != nil {
				respond(w, 503, map[string]string{"error": "VPN操作失败，请核实执行器状态"})
				return
			}
			respond(w, 200, e.Status())
		})
	}
	return mux
}

// Client 的连接固定到Unix socket，环境代理与HTTP重定向均禁用。
type Client struct{ http *http.Client }

// NewClient 不接受动态服务URL，避免控制面被引向公网或其他本地服务。
func NewClient(socket string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}
	return &Client{http: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) request(ctx context.Context, method, path string, body []byte) (State, error) {
	r, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, bytes.NewReader(body))
	if err != nil {
		return State{}, err
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(r)
	if err != nil {
		return State{}, errors.New("无法连接VPN执行器")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return State{}, errors.New("VPN执行器拒绝操作")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4096))
	decoder.DisallowUnknownFields()
	var state State
	if err = decoder.Decode(&state); err != nil {
		return State{}, errors.New("VPN执行器响应无效")
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return State{}, errors.New("VPN执行器响应无效")
	}
	return state, nil
}

// Check 只验证结构化目标，不要求运行状态与待验证配置相同。
func (c *Client) Check(ctx context.Context, d vpn.Desired) error {
	body, err := vpn.EncodeCommand(d)
	if err != nil {
		return err
	}
	_, err = c.request(ctx, "POST", "/check", body)
	return err
}

// Apply 核对实际运行状态与目标指纹；进程未启动不能被误报为成功。
func (c *Client) Apply(ctx context.Context, d vpn.Desired) error {
	body, err := vpn.EncodeCommand(d)
	if err != nil {
		return err
	}
	state, err := c.request(ctx, "POST", "/apply", body)
	if err != nil {
		return err
	}
	if state.Fingerprint != vpn.CommandFingerprint(d) || state.Enabled != d.Enabled || state.Running != d.Enabled {
		return errors.New("VPN实际状态与目标不一致")
	}
	return nil
}

// Status 仅返回非秘密的执行状态。
func (c *Client) Status(ctx context.Context) (State, error) {
	return c.request(ctx, "GET", "/status", nil)
}

// Component 将数据库密文转换为受限Unix命令，密钥只存在控制服务中。
type Component struct {
	Key    []byte
	Runner *Client
}

// Check 解密完整性失败时不发送任何执行器请求。
func (c *Component) Check(ctx context.Context, value string) error {
	desired, err := vpn.Open(c.Key, value)
	if err != nil {
		return err
	}
	return c.Runner.Check(ctx, desired)
}

// Apply 不向runner提供主密钥或数据库，runner只收到本次运行所需秘密。
func (c *Component) Apply(ctx context.Context, value string) error {
	desired, err := vpn.Open(c.Key, value)
	if err != nil {
		return err
	}
	return c.Runner.Apply(ctx, desired)
}

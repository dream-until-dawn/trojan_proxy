// Package vpnrunner 管理固定VPN子进程，只接受结构化Trojan命令。
package vpnrunner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

// State 的指纹仅供配置一致性确认；不返回密码、原始配置或进程输出。
type State struct {
	Enabled     bool   `json:"enabled"`
	Running     bool   `json:"running"`
	Fingerprint string `json:"fingerprint"`
}

type process struct {
	cmd  *exec.Cmd
	done chan struct{}
}

// Engine 在自己的tmpfs目录保存运行配置，不接受调用者指定文件名或命令。
type Engine struct {
	mu                sync.Mutex
	settings          vpn.Settings
	binary, directory string
	current           vpn.Desired
	child             *process
}

// NewEngine 由固定部署参数创建；目录必须专用于runner且不得是符号链接。
func NewEngine(settings vpn.Settings, binary, directory string) (*Engine, error) {
	if !filepath.IsAbs(binary) || !filepath.IsAbs(directory) {
		return nil, errors.New("执行器路径必须是绝对路径")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	stat, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && stat.Mode().Perm()&0077 != 0) {
		return nil, errors.New("执行器目录必须是当前用户专用0700目录")
	}
	return &Engine{settings: settings, binary: binary, directory: directory}, nil
}

func (e *Engine) writeTemp(body string) (string, error) {
	f, err := os.CreateTemp(e.directory, ".config-")
	if err != nil {
		return "", err
	}
	name := f.Name()
	_, err = f.WriteString(body)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

func (e *Engine) check(ctx context.Context, d vpn.Desired) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	body, err := vpn.CompileTrojan(e.settings, d)
	if err != nil {
		return "", err
	}
	if body == "" {
		return body, nil
	}
	name, err := e.writeTemp(body)
	if err != nil {
		return "", err
	}
	defer os.Remove(name)
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(bounded, e.binary, "check", "-c", name)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Run(); err != nil {
		return "", errors.New("VPN引擎配置校验失败")
	}
	return body, nil
}

// Check 不改变当前进程或运行配置；检查文件始终0600且及时删除。
func (e *Engine) Check(ctx context.Context, d vpn.Desired) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := e.check(ctx, d)
	return err
}

func alive(p *process) bool {
	if p == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (e *Engine) state() State {
	return State{Enabled: e.current.Enabled, Running: alive(e.child), Fingerprint: vpn.CommandFingerprint(e.current)}
}

// Status 不返回任何原始配置；进程意外退出会立即反映为running=false。
func (e *Engine) Status() State { e.mu.Lock(); defer e.mu.Unlock(); return e.state() }

func (e *Engine) stop() error {
	p := e.child
	if p == nil {
		return nil
	}
	if alive(p) {
		p.cmd.Process.Signal(os.Interrupt)
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return errors.New("无法停止VPN进程")
			}
			select {
			case <-p.done:
			case <-time.After(2 * time.Second):
				return errors.New("VPN进程停止超时")
			}
		}
	}
	e.child = nil
	return nil
}

func (e *Engine) start(ctx context.Context, d vpn.Desired, body string) error {
	if !d.Enabled {
		return nil
	}
	name, err := e.writeTemp(body)
	if err != nil {
		return err
	}
	defer os.Remove(name)
	path := filepath.Join(e.directory, "config.json")
	if err = os.Rename(name, path); err != nil {
		return err
	}
	cmd := exec.Command(e.binary, "run", "-c", path)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return errors.New("VPN进程无法启动")
	}
	p := &process{cmd: cmd, done: make(chan struct{})}
	e.child = p
	go func() { cmd.Wait(); close(p.done) }()
	if err = e.waitReady(ctx, d, p); err != nil {
		return errors.Join(err, e.stop())
	}
	return nil
}

func (e *Engine) waitReady(ctx context.Context, d vpn.Desired, p *process) error {
	// 使用已发布的确切叶证书作为信任锚，核对实际监听者，避免把别的占端口进程当成功。
	file, err := os.Open(filepath.Join("/certificates", d.CertificateVersion, "fullchain.pem"))
	if err != nil {
		return errors.New("无法读取VPN发布证书")
	}
	body, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	file.Close()
	if err != nil || len(body) > 1024*1024 {
		return errors.New("VPN发布证书无效")
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return errors.New("VPN发布证书无效")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.New("VPN发布证书无效")
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !alive(p) {
			return errors.New("VPN进程在启动期间退出")
		}
		dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 300 * time.Millisecond}, Config: &tls.Config{RootCAs: roots, ServerName: e.settings.Domain, MinVersion: tls.VersionTLS12}}
		connection, err := dialer.DialContext(bounded, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(e.settings.Port)))
		if err == nil {
			actual := connection.(*tls.Conn).ConnectionState().PeerCertificates
			connection.Close()
			if len(actual) == 0 || !bytes.Equal(actual[0].Raw, leaf.Raw) {
				return errors.New("VPN实际监听证书与发布版本不一致")
			}
			// 启动后留出短暂观察期，防止进程刚退出而同端口外部服务碰巧握手成功。
			select {
			case <-p.done:
				return errors.New("VPN进程在监听后退出")
			case <-bounded.Done():
				return bounded.Err()
			case <-time.After(150 * time.Millisecond):
				return nil
			}
		}
		select {
		case <-p.done:
			return errors.New("VPN进程在启动期间退出")
		case <-bounded.Done():
			return errors.New("VPN监听或证书握手未就绪")
		case <-ticker.C:
		}
	}
}

// Apply 先校验再替换；启动失败时重新启动旧配置，保留实际失败信息。
func (e *Engine) Apply(ctx context.Context, d vpn.Desired) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	body, err := e.check(ctx, d)
	if err != nil {
		return err
	}
	if e.current == d && (!d.Enabled || alive(e.child)) {
		return nil
	}
	previous := e.current
	if err = e.stop(); err != nil {
		return err
	}
	if err = e.start(ctx, d, body); err != nil {
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 7*time.Second)
		defer cancel()
		oldBody, checkErr := e.check(recovery, previous)
		if checkErr == nil {
			checkErr = e.start(recovery, previous, oldBody)
		}
		return errors.Join(err, checkErr)
	}
	e.current = d
	if !d.Enabled {
		os.Remove(filepath.Join(e.directory, "config.json"))
	}
	return nil
}

// Close 优雅退出子进程，调用者随后关闭Unix监听器；不删除持久证书和业务数据。
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	err := e.stop()
	os.Remove(filepath.Join(e.directory, "config.json"))
	return err
}

//go:build linux

package deployment

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
)

func fixture(t *testing.T) (config.Config, Paths) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("初始化测试需root和专用容器")
	}
	root := t.TempDir()
	paths := Paths{Data: filepath.Join(root, "data"), GatewayRun: filepath.Join(root, "gateway"), VPNRun: filepath.Join(root, "vpn"), Certificates: filepath.Join(root, "certificates"), CaddyData: filepath.Join(root, "cache")}
	return config.Config{Version: 1, AdminPort: 8007, ControlPort: 18090, VPNPort: 18443, DataDir: paths.Data, StandardIngress: true}, paths
}

func TestPrepareFreshRepeatAndVolumePermissions(t *testing.T) {
	c, p := fixture(t)
	for range 2 {
		if err := Prepare(context.Background(), c, p); err != nil {
			t.Fatal(err)
		}
	}
	for _, expected := range []volume{{p.Data, "control-data", 10001, 0700}, {p.VPNRun, "vpn-run", 10002, 0770}, {p.GatewayRun, "gateway-run", 10001, 0770}} {
		info, err := os.Stat(expected.path)
		if err != nil {
			t.Fatal(err)
		}
		owner := info.Sys().(*syscall.Stat_t)
		if info.Mode().Perm() != expected.mode || owner.Uid != uint32(expected.uid) || owner.Gid != 10001 {
			t.Fatal("prepared volume permissions incorrect", expected.role, info.Mode(), owner.Uid)
		}
	}
	body, err := os.ReadFile(filepath.Join(p.GatewayRun, "bootstrap.json"))
	if err != nil || !strings.Contains(string(body), `":80"`) || !strings.Contains(string(body), `":443"`) || strings.Contains(string(body), `":8007"`) || strings.Contains(string(body), "load_files") {
		t.Fatal("bootstrap exposed management or missed reserved ports", err)
	}
}

func TestPreparePortConflictStartsNoVolumeWork(t *testing.T) {
	for _, port := range []string{"80", "443"} {
		t.Run(port, func(t *testing.T) {
			c, p := fixture(t)
			listener, err := net.Listen("tcp4", "0.0.0.0:"+port)
			if err != nil {
				t.Fatal(err)
			}
			err = Prepare(context.Background(), c, p)
			listener.Close()
			if err == nil || !strings.Contains(err.Error(), "端口"+port+"不可用") {
				t.Fatal("occupied standard port did not prevent startup", port, err)
			}
			if _, err = os.Stat(p.Data); !os.IsNotExist(err) {
				t.Fatal("port conflict changed deployment volumes", err)
			}
		})
	}
}

func TestPrepareRejectsUnknownVolumeAndTrustedSocketRequired(t *testing.T) {
	c, p := fixture(t)
	if err := os.Mkdir(p.Data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Data, "foreign.txt"), []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(context.Background(), c, p); err == nil {
		t.Fatal("unmarked nonempty volume adopted")
	}
	b, err := os.ReadFile(filepath.Join(p.Data, "foreign.txt"))
	if err != nil || string(b) != "untouched" {
		t.Fatal("foreign volume modified", err)
	}
	// 使用另外一套空卷，构造真实Unix socket及真实被占端口验证重复启动识别。
	c, p = fixture(t)
	if err = Prepare(context.Background(), c, p); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(p.GatewayRun, "admin.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"apps":{"http":{"servers":{"public_80":{"listen":[":80"]},"public_443":{"listen":[":443"]}}}}}`))
	})}
	defer server.Close()
	go server.Serve(listener)
	occupied, err := net.Listen("tcp4", "0.0.0.0:80")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if err = Prepare(context.Background(), c, p); err == nil {
		t.Fatal("untrusted socket bypassed port preflight")
	}
	if err = os.Chown(socket, 10001, 10001); err != nil {
		t.Fatal(err)
	}
	if err = Prepare(context.Background(), c, p); err != nil {
		t.Fatal("owned running gateway rejected on repeated startup", err)
	}
}

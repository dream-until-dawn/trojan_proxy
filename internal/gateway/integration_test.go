//go:build integration

package gateway_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/files"
	"github.com/dream-until-dawn/trojan_proxy/internal/gateway"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	"github.com/dream-until-dawn/trojan_proxy/internal/routing"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func port(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func fetch(t *testing.T, port int, path string) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, err := client.Get("http://127.0.0.1:" + strconv.Itoa(port) + path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return r.StatusCode, string(body)
}

func TestRealGatewayLifecycle(t *testing.T) {
	ctx := context.Background()
	engine := gateway.NewClient("/run/caddy/admin.sock")
	var settings gateway.Settings
	var backendPort int
	first := os.Getenv("TROJAN_GATEWAY_PHASE") == "first"
	if first {
		settings = gateway.Settings{Domain: "localhost", AdminPort: port(t), ControlPort: port(t), FilePort: port(t), Socket: "/run/caddy/admin.sock"}
		backendPort = port(t)
		settings.Policy = routes.Policy{AdminPort: settings.AdminPort, ControlPort: settings.ControlPort, FilePort: settings.FilePort, VPNPort: 18443, Directories: map[string]string{"demo": "/public/demo"}}
	} else {
		body, err := os.ReadFile("/state/settings.json")
		if err != nil {
			t.Fatal(err)
		}
		var saved struct {
			Settings    gateway.Settings
			BackendPort int
		}
		if err = json.Unmarshal(body, &saved); err != nil {
			t.Fatal(err)
		}
		settings, backendPort = saved.Settings, saved.BackendPort
	}
	backendListener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(backendPort))
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "upstream:"+r.URL.Path) }))
	backend.Listener = backendListener
	backend.Start()
	defer backend.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err = engine.Current(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("非root进程无法访问网关Unix socket", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if first {
		baseline, err := gateway.Compile(settings, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = engine.Apply(ctx, baseline); err != nil {
			t.Fatal("基线配置应用失败", err)
		}
	}
	store, err := storage.OpenJournal(ctx, "/state/state.db", control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service := routing.NewService(store, engine, settings)
	if first {
		if err = os.MkdirAll("/public/demo", 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile("/public/demo/report.txt", []byte("file-sentinel"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := files.OpenRoot("/public/demo")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fileListener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(settings.FilePort))
	if err != nil {
		t.Fatal(err)
	}
	fileServer := httptest.NewUnstartedServer(&files.Handler{Roots: map[string]*files.Root{"demo": root}, Resolver: service})
	fileServer.Listener = fileListener
	fileServer.Start()
	defer fileServer.Close()
	var ruleset []routes.Rule
	if first {
		publicPort := port(t)
		ruleset = []routes.Rule{{ID: "app", Name: "应用", Port: publicPort, Path: "/app", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: backendPort, StripPrefix: true},
			{ID: "files_rule", Name: "下载", Port: publicPort, Path: "/downloads", Kind: "files", DirectoryID: "demo", Browse: true}}
		if err = service.Apply(ctx, 1, ruleset); err != nil {
			t.Fatal("真实规则未生效", err)
		}
		occupied, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer occupied.Close()
		bad := append([]routes.Rule(nil), ruleset...)
		bad = append(bad, routes.Rule{ID: "conflict", Name: "故意占用", Port: occupied.Addr().(*net.TCPAddr).Port, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: backendPort})
		if err = service.Apply(ctx, 2, bad); err == nil {
			t.Fatal("端口冲突未拒绝")
		}
		state, err := service.List(ctx)
		if err != nil || state.Revision != 2 || state.Pending || len(state.Rules) != 2 {
			t.Fatal("冲突后实际修订不一致", state, err)
		}
		body, err := json.Marshal(struct {
			Settings    gateway.Settings
			BackendPort int
		}{settings, backendPort})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile("/state/settings.json", body, 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		if err = service.Reconcile(ctx); err != nil {
			t.Fatal("实际网关重启后恢复失败", err)
		}
		state, err := service.List(ctx)
		if err != nil || state.Revision != 2 {
			t.Fatal("持久化修订未恢复", state, err)
		}
		ruleset = state.Rules
	}
	publicPort := ruleset[0].Port
	if status, body := fetch(t, publicPort, "/app/hello"); status != 200 || body != "upstream:/hello" {
		t.Fatal("实际反代或前缀剥离错误", status, body)
	}
	if status, _ := fetch(t, publicPort, "/apple/hello"); status != 404 {
		t.Fatal("路径边界匹配错误", status)
	}
	if status, body := fetch(t, publicPort, "/downloads/report.txt"); status != 200 || body != "file-sentinel" {
		t.Fatal("实际目录下载失败", status, body)
	}
	if status, body := fetch(t, publicPort, "/downloads/"); status != 200 || !strings.Contains(body, `href="./report.txt"`) {
		t.Fatal("实际索引链接错误", status, body)
	}
	if status, _ := fetch(t, publicPort, "/downloads"); status != 301 {
		t.Fatal("目录标准化跳转失败", status)
	}
}

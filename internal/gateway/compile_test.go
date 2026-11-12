package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

func TestCompileRetainsAdminAndSegmentBoundary(t *testing.T) {
	settings := Settings{Domain: "qin-xin.top", AdminPort: 8007, ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443}}
	r := routes.Rule{ID: "app", Name: "应用", Port: 18001, Path: "/app", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3000}
	body, err := Compile(settings, []routes.Rule{r})
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal([]byte(body), &root); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"path":["/app","/app/*"]`) {
		t.Fatal("路径应按段匹配，不能使用/app*")
	}
	if !strings.Contains(body, `"dial":"127.0.0.1:18090"`) || !strings.Contains(body, `":8007"`) {
		t.Fatal("业务规则覆盖后台")
	}
	r.Port = 8007
	if _, err = Compile(settings, []routes.Rule{r}); err == nil {
		t.Fatal("后台端口覆盖未拒绝")
	}
}

func TestInternalTransportDoesNotChangeUserUpstream(t *testing.T) {
	s := Settings{Domain: "localhost", AdminPort: 8007, ControlPort: 18090, FilePort: 18091,
		Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443, Directories: map[string]string{"demo": "/public/demo"}}}
	rules := []routes.Rule{
		{ID: "files", Name: "目录", Port: 18001, Path: "/", Kind: "files", DirectoryID: "demo"},
		{ID: "app", Name: "应用", Port: 18002, Path: "/", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3000},
	}
	body, err := Compile(s, rules)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal([]byte(body), &root); err != nil {
		t.Fatal(err)
	}
	servers := root["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, name := range []string{"admin", "public_18001", "public_18002"} {
		found := 0
		for _, route := range servers[name].(map[string]any)["routes"].([]any) {
			for _, handler := range route.(map[string]any)["handle"].([]any) {
				h := handler.(map[string]any)
				if h["handler"] != "reverse_proxy" {
					continue
				}
				found++
				transport, exists := h["transport"]
				if name == "public_18002" {
					if exists {
						t.Fatal("user upstream transport changed")
					}
					continue
				}
				if !exists || transport.(map[string]any)["keep_alive"].(map[string]any)["enabled"] != false {
					t.Fatal("internal connection reuse was not disabled")
				}
			}
		}
		if found != 1 {
			t.Fatalf("unexpected proxy count %s %d", name, found)
		}
	}
}

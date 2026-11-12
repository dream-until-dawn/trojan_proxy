package gateway

import (
	"encoding/json"
	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	"strings"
	"testing"
)

func pathFixture() Settings {
	return Settings{Domain: "qin-xin.top", AdminPort: 8007, AdminPath: "/proxy", ControlPort: 18090, FilePort: 18091, Socket: "/run/caddy/admin.sock", Ingress: &Ingress{Mode: "automatic"}, Policy: routes.Policy{AdminPort: 8007, ControlPort: 18090, FilePort: 18091, VPNPort: 18443, AllowStandardPorts: true}}
}
func pathServers(t *testing.T, body string) map[string]any {
	t.Helper()
	var root map[string]any
	if err := json.Unmarshal([]byte(body), &root); err != nil {
		t.Fatal(err)
	}
	return root["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
}
func TestAdminPathPriorityAndTransition(t *testing.T) {
	s := pathFixture()
	rule := routes.Rule{ID: "business", Name: "期货", Port: 443, Host: s.Domain, Path: "/futures", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3030, HTTPS: true}
	body, err := Compile(s, []routes.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	servers := pathServers(t, body)
	if _, ok := servers["admin"]; ok || strings.Contains(body, `":8007"`) {
		t.Fatal("path mode retained legacy admin listener")
	}
	public := servers["public_443"].(map[string]any)
	encoded, _ := json.Marshal(public["routes"])
	text := string(encoded)
	admin := strings.Index(text, `"/proxy"`)
	business := strings.Index(text, `"/futures"`)
	if admin < 0 || business < admin || !strings.Contains(text, `"/proxy/*"`) {
		t.Fatal("management path did not precede business with segment boundary", text)
	}
	old := s
	old.AdminPath = ""
	dual, err := CompileAdminTransition(old, s, []routes.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	servers = pathServers(t, dual)
	if servers["admin"] == nil || !strings.Contains(dual, `"/proxy/*"`) || !strings.Contains(dual, `"/futures/*"`) {
		t.Fatal("dual transition lost old entry or business")
	}
	// 候选路径不能盖住已发布业务，即便编译候选时通常不重编译业务规则。
	conflict := rule
	conflict.Path = "/proxy/private"
	if _, err = CompileAdminTransition(old, s, []routes.Rule{conflict}); err == nil {
		t.Fatal("candidate management path shadowed existing business")
	}
	conflict.Path = "/proxy"
	if _, err = Compile(s, []routes.Rule{conflict}); err == nil {
		t.Fatal("business occupied management path")
	}
	// 根业务路由允许存在，管理入口由优先级保护。
	rule.Path = "/"
	if _, err = Compile(s, []routes.Rule{rule}); err != nil {
		t.Fatal(err)
	}
	s.Ingress = nil
	if _, err = Compile(s, nil); err == nil {
		t.Fatal("path entry without standard HTTPS accepted")
	}
}

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

package gateway

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// Settings 来自部署配置，不允许经Web覆盖后台地址、证书路径或管理socket。
type Settings struct {
	Domain                           string
	AdminPort, ControlPort, FilePort int
	Socket                           string
	Policy                           routes.Policy
}

// Compile 生成完整配置，始终保留后台入口，绝不拼接原始配置文本。
func Compile(settings Settings, rules []routes.Rule) (string, error) {
	if err := routes.ValidateSet(rules, settings.Policy); err != nil {
		return "", err
	}
	serverRoutes := map[int][]any{}
	ordered := append([]routes.Rule(nil), rules...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if (ordered[i].Host != "") != (ordered[j].Host != "") {
			return ordered[i].Host != ""
		}
		return len(ordered[i].Path) > len(ordered[j].Path)
	})
	for _, r := range ordered {
		match := map[string]any{}
		if r.Host != "" {
			match["host"] = []string{r.Host}
		}
		if r.Path != "/" {
			match["path"] = []string{r.Path, r.Path + "/*"}
		}
		var handles []any
		if (r.StripPrefix || r.Kind == "files") && r.Path != "/" {
			handles = append(handles, map[string]any{"handler": "rewrite", "strip_path_prefix": r.Path})
		}
		upstream := net.JoinHostPort(r.UpstreamIP, strconv.Itoa(r.UpstreamPort))
		if r.Kind == "files" {
			handles = append(handles, map[string]any{"handler": "rewrite", "uri": "/" + r.ID + "{http.request.uri}"})
			upstream = net.JoinHostPort("127.0.0.1", strconv.Itoa(settings.FilePort))
		}
		proxy := map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": upstream}}}
		if r.Kind == "files" {
			proxy["headers"] = map[string]any{"request": map[string]any{"set": map[string]any{"X-Trojan-Original-URI": []string{"{http.request.orig_uri}"}}}}
		}
		handles = append(handles, proxy)
		serverRoutes[r.Port] = append(serverRoutes[r.Port], map[string]any{"match": []any{match}, "handle": handles, "terminal": true})
	}
	servers := map[string]any{}
	for port, rs := range serverRoutes {
		rs = append(rs, map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 404}}})
		server := map[string]any{"listen": []string{fmt.Sprintf(":%d", port)}, "automatic_https": map[string]any{"disable": true}, "routes": rs}
		if port == 443 {
			server["tls_connection_policies"] = []any{map[string]any{}}
		}
		servers[fmt.Sprintf("public_%d", port)] = server
	}
	servers["admin"] = map[string]any{"listen": []string{fmt.Sprintf(":%d", settings.AdminPort)}, "automatic_https": map[string]any{"disable": true}, "tls_connection_policies": []any{map[string]any{}},
		"routes": []any{map[string]any{"match": []any{map[string]any{"host": []string{settings.Domain}}}, "handle": []any{map[string]any{"handler": "reverse_proxy", "upstreams": []any{map[string]any{"dial": net.JoinHostPort("127.0.0.1", strconv.Itoa(settings.ControlPort))}}}}}}}
	root := map[string]any{"admin": map[string]any{"listen": "unix/" + settings.Socket + "|0660"}, "apps": map[string]any{
		"http": map[string]any{"servers": servers}, "tls": map[string]any{"certificates": map[string]any{"load_files": []any{map[string]any{"certificate": "/certs/fullchain.cer", "key": "/certs/private.key"}}}}}}
	body, err := json.Marshal(root)
	return string(body), err
}

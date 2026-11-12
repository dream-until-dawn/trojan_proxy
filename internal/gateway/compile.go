package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// Fingerprint 将编译格式和部署设置绑定到持久快照，升级后不能恢复旧编译策略。
func Fingerprint(settings Settings) (string, error) {
	body, err := json.Marshal(struct {
		Version  int
		Settings Settings
	}{Version: 6, Settings: settings})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}

// Settings 来自部署配置，不允许经Web覆盖后台地址、证书路径或管理socket。
type Settings struct {
	Domain                           string
	AdminPort, ControlPort, FilePort int
	Socket                           string
	Policy                           routes.Policy
	Ingress                          *Ingress
}

// Compile 生成完整配置，始终保留后台入口，绝不拼接原始配置文本。
func Compile(settings Settings, rules []routes.Rule) (string, error) {
	if err := validateIngress(settings, rules); err != nil {
		return "", &routes.ValidationError{Cause: err}
	}
	if err := routes.ValidateSet(rules, settings.Policy); err != nil {
		return "", err
	}
	serverRoutes := map[int][]any{}
	securePorts := map[int]bool{}
	ordered := append([]routes.Rule(nil), rules...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if (ordered[i].Host != "") != (ordered[j].Host != "") {
			return ordered[i].Host != ""
		}
		return len(ordered[i].Path) > len(ordered[j].Path)
	})
	for _, r := range ordered {
		if r.HTTPS {
			securePorts[r.Port] = true
		}
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
		if r.HTTPS {
			proxy["transport"] = internalTransport()
		}
		if r.Kind == "files" {
			proxy["transport"] = internalTransport()
			proxy["headers"] = map[string]any{"request": map[string]any{"set": map[string]any{"X-Trojan-Original-URI": []string{"{http.request.orig_uri}"}}}}
		}
		handles = append(handles, proxy)
		listenPort := r.Port
		if settings.Ingress != nil && settings.Domain != "" && !settings.Ingress.AwaitCertificate && settings.Ingress.Mode != "unavailable" && r.Port == 80 {
			// 标准HTTP规则代表公开网站入口；域名模式实际由HTTPS承载。
			listenPort = 443
		}
		serverRoutes[listenPort] = append(serverRoutes[listenPort], map[string]any{"match": []any{match}, "handle": handles, "terminal": true})
	}
	servers := map[string]any{}
	for port, rs := range serverRoutes {
		fallback := notFound()
		if settings.Ingress != nil && (port == 80 || port == 443) {
			var err error
			fallback, err = welcomeForSettings(settings)
			if err != nil {
				return "", err
			}
		}
		rs = append(rs, fallback)
		server := map[string]any{"listen": []string{fmt.Sprintf(":%d", port)}, "automatic_https": map[string]any{"disable": true}, "routes": rs}
		if port == 443 || securePorts[port] {
			server["tls_connection_policies"] = []any{map[string]any{}}
		}
		if securePorts[port] && port != 443 {
			server["tls_connection_policies"] = []any{
				map[string]any{"match": map[string]any{"sni": []string{settings.Domain}}},
				map[string]any{"drop": true},
			}
		}
		servers[fmt.Sprintf("public_%d", port)] = server
	}
	servers["admin"] = map[string]any{"listen": []string{fmt.Sprintf(":%d", settings.AdminPort)}, "automatic_https": map[string]any{"disable": true}, "tls_connection_policies": []any{map[string]any{}},
		"routes": []any{map[string]any{"match": []any{map[string]any{"host": []string{settings.Domain}}}, "handle": []any{map[string]any{"handler": "reverse_proxy", "transport": internalTransport(), "upstreams": []any{map[string]any{"dial": net.JoinHostPort("127.0.0.1", strconv.Itoa(settings.ControlPort))}}}}}}}
	tlsApp := map[string]any{"certificates": map[string]any{"load_files": []any{map[string]any{"certificate": "/certs/fullchain.cer", "key": "/certs/private.key"}}}}
	if settings.Ingress != nil {
		if err := configureIngress(settings, servers, tlsApp); err != nil {
			return "", err
		}
	}
	for name, value := range servers {
		domain := ""
		if name == "admin" || (settings.Domain != "" && (name == "public_80" || name == "public_443")) {
			domain = settings.Domain
		}
		crawlPolicy(value.(map[string]any), domain)
		// 首版不开放UDP/HTTP3，避免TCP预检通过但UDP监听冲突。
		value.(map[string]any)["protocols"] = []string{"h1", "h2"}
	}
	root := map[string]any{"admin": map[string]any{"listen": "unix/" + settings.Socket + "|0660"}, "apps": map[string]any{
		"http": map[string]any{"servers": servers}, "tls": tlsApp}}
	body, err := json.Marshal(root)
	return string(body), err
}

// internalTransport 为低流量内置服务逐次建立回环连接，避开上游空闲关闭与复用的竞争。
// 不对POST重试，避免管理写入被重复执行；用户自定义业务上游仍保留引擎默认策略。
func internalTransport() map[string]any {
	return map[string]any{"protocol": "http", "keep_alive": map[string]any{"enabled": false}}
}

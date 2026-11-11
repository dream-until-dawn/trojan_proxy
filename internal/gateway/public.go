package gateway

import "github.com/dream-until-dawn/trojan_proxy/internal/welcome"

const robotsTag = "noindex, nofollow, noarchive, nosnippet"

func welcomeRoute(domain string) (any, error) {
	body, err := welcome.Render(domain, true)
	if err != nil {
		return nil, err
	}
	return map[string]any{"handle": []any{map[string]any{"handler": "static_response", "status_code": 200, "body": body, "headers": map[string]any{"Content-Type": []string{"text/html; charset=utf-8"}, "Cache-Control": []string{"no-store"}, "X-Content-Type-Options": []string{"nosniff"}, "Content-Security-Policy": []string{"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}}}}, "terminal": true}, nil
}

// crawlPolicy 在业务规则前保留robots路径，deferred响应头覆盖反代上游的索引许可。
func crawlPolicy(server map[string]any, domain string) {
	header := map[string]any{"handle": []any{map[string]any{"handler": "headers", "response": map[string]any{"set": map[string]any{"X-Robots-Tag": []string{robotsTag}}, "deferred": true}}}}
	match := map[string]any{"path": []string{"/robots.txt"}}
	if domain != "" {
		match["host"] = []string{domain}
	}
	robots := map[string]any{"match": []any{match}, "handle": []any{map[string]any{"handler": "static_response", "status_code": 200, "body": "User-agent: *\nDisallow: /\n", "headers": map[string]any{"Content-Type": []string{"text/plain; charset=utf-8"}}}}, "terminal": true}
	server["routes"] = append([]any{header, robots}, server["routes"].([]any)...)
}

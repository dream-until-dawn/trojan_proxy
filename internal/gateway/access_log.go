package gateway

import (
	"fmt"
	"net"
)

// configureAccessLog 在网关编码阶段删除秘密；磁盘缓冲和错误输出都不接收原始请求头或查询参数。
func configureAccessLog(root, servers map[string]any) {
	encoder := map[string]any{"format": "filter", "wrap": map[string]any{"format": "json"}, "fields": map[string]any{
		"request>headers": map[string]any{"filter": "delete"}, "resp_headers": map[string]any{"filter": "delete"},
		"request>tls": map[string]any{"filter": "delete"},
		"request>uri": map[string]any{"filter": "regexp", "regexp": `(?i)^https?://[^/]*|\?.*$|^[^/*].*$`, "value": ""},
	}}
	for _, value := range servers {
		server := value.(map[string]any)
		listen := server["listen"].([]string)
		_, port, _ := net.SplitHostPort(listen[0])
		server["logs"] = map[string]any{"default_logger_name": fmt.Sprintf("web_access.p%s", port)}
	}
	root["logging"] = map[string]any{"logs": map[string]any{
		"default": map[string]any{"exclude": []string{"http.log.access"}, "encoder": encoder},
		"web_access": map[string]any{"include": []string{"http.log.access.web_access"}, "encoder": encoder,
			"writer": map[string]any{"output": "file", "filename": "/data/access/requests.log", "mode": "0600",
				"roll_size_mb": 16, "roll_interval": int64(3600000000000), "roll_minutes": []int{0}, "roll_keep": 8, "roll_keep_days": 1, "roll_compression": "none"}},
	}}
}

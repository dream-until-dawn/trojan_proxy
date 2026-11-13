package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAccessLoggingEveryServerAndPrivacyEncoder(t *testing.T) {
	// 复用标准编译夹具，测试同时检查logger入口与编码层过滤，不能仅依赖入库脱敏。
	servers := map[string]any{"public_80": map[string]any{"listen": []string{":80"}}, "public_443": map[string]any{"listen": []string{":443"}}, "admin": map[string]any{"listen": []string{":8007"}}}
	root := map[string]any{}
	configureAccessLog(root, servers)
	for name, v := range servers {
		if v.(map[string]any)["logs"] == nil {
			t.Fatal("HTTP入口未启用全量记录", name)
		}
	}
	logs := root["logging"].(map[string]any)["logs"].(map[string]any)
	encoder := logs["web_access"].(map[string]any)["encoder"].(map[string]any)
	fields := encoder["fields"].(map[string]any)
	for _, field := range []string{"request>headers", "resp_headers", "request>tls"} {
		if fields[field].(map[string]any)["filter"] != "delete" {
			t.Fatal("落盘前隐私过滤缺失", field)
		}
	}
	if fields["request>uri"].(map[string]any)["filter"] != "regexp" {
		t.Fatal("查询参数未在落盘前移除")
	}
	body, _ := json.Marshal(root)
	if !strings.Contains(string(body), `"roll_interval":3600000000000`) || !strings.Contains(string(body), `"roll_minutes":[0]`) || !strings.Contains(string(body), `"roll_keep":8`) {
		t.Fatal("日志未设置时间与容量轮转")
	}
}

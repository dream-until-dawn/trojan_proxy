package vpnrunner

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

func TestRunnerRejectsRawEngineAndExtraCommands(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	engine, err := NewEngine(vpn.Settings{}, filepath.Join(t.TempDir(), "absent-engine"), directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"command":"sh"}`, `{"enabled":false,"password":"secret"}`, `{"inbounds":[]}`, `{} {}`, strings.Repeat("x", 5000)} {
		r := httptest.NewRequest("POST", "http://localhost/apply", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		engine.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("执行器接受任意配置或秘密停止命令", w.Code)
		}
	}
	if err = engine.Apply(context.Background(), vpn.Desired{}); err != nil {
		t.Fatal("停止状态错误依赖引擎文件", err)
	}
	if state := engine.Status(); state.Enabled || state.Running {
		t.Fatal("停止状态不一致")
	}
}

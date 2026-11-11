package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func TestAPIOriginAuthenticationAndLogout(t *testing.T) {
	ctx := context.Background()
	db, err := storage.OpenJournal(ctx, filepath.Join(t.TempDir(), "state.db"), control.Revision{Number: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := auth.EncryptSecret(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword("test-long-random-password")
	if err != nil {
		t.Fatal(err)
	}
	if err = db.CreateAccount(ctx, storage.Account{PasswordHash: hash, Secret: encrypted, LastCounter: -1, Recovery: []string{auth.TokenHash("test-recovery-code")}}); err != nil {
		t.Fatal(err)
	}
	origin := "https://qin-xin.top:8007"
	handler := (&Server{Auth: auth.NewService(db, key), Origins: map[string]bool{origin: true}}).Handler()
	call := func(method, path, source, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Host = "qin-xin.top:8007"
		r.Header.Set("Origin", source)
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := call("POST", "/api/status", origin, "", "{}"); w.Code != 401 {
		t.Fatalf("未认证读取未拒绝: %d", w.Code)
	}
	w := call("POST", "/api/login", origin, "", `{"password":"test-long-random-password","recovery":"test-recovery-code"}`)
	if w.Code != 200 {
		t.Fatalf("合法登录失败: %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Fatal("令牌不应通过Cookie发放")
	}
	var result struct {
		Token string `json:"token"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Token == "" {
		t.Fatal("令牌响应无效", err)
	}
	if w = call("POST", "/api/status", origin, result.Token, "{}"); w.Code != 200 {
		t.Fatal("合法认证读取失败", w.Code)
	}
	for _, badOrigin := range []string{"https://qin-xin.top:8008", "https://evil.example", ""} {
		if w = call("POST", "/api/logout", badOrigin, result.Token, "{}"); w.Code != 403 {
			t.Fatalf("跨来源未拒绝: %q %d", badOrigin, w.Code)
		}
	}
	if w = call("POST", "/api/status", origin, result.Token, "{}"); w.Code != 200 {
		t.Fatal("被拒绝的退出请求不应影响会话")
	}
	if w = call("POST", "/api/logout", origin, result.Token, "{}"); w.Code != 200 {
		t.Fatal("退出失败")
	}
	if w = call("POST", "/api/status", origin, result.Token, "{}"); w.Code != 401 {
		t.Fatal("退出令牌仍有效")
	}
	if w = call("POST", "/api/login", origin, "", `{"password":"test-long-random-password","recovery":"test-recovery-code"}`); w.Code != 401 {
		t.Fatal("恢复码重复使用通过")
	}
	if w = call("POST", "/api/login", origin, "", `{} {}`); w.Code != 400 {
		t.Fatal("拼接JSON未拒绝")
	}
	r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader("{}"))
	r.Host = "evil.example"
	r.Header.Set("Origin", origin)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 421 {
		t.Fatal("非法Host未拒绝")
	}
}

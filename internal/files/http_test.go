package files

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

type resolver struct{ rule routes.Rule }

func (r resolver) PublicRule(_ context.Context, id string) (routes.Rule, error) {
	if id != r.rule.ID {
		return routes.Rule{}, errors.New("missing")
	}
	return r.rule, nil
}
func TestPublicFilesAndIndexBoundary(t *testing.T) {
	base := t.TempDir()
	public := filepath.Join(base, "public")
	if err := os.Mkdir(public, 0700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"report.txt": "public-data", ".env": "hidden-secret"} {
		if err := os.WriteFile(filepath.Join(public, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "outside"), []byte("outside-sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(public)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	rule := routes.Rule{ID: "download", Kind: "files", DirectoryID: "public", Path: "/downloads", Browse: false}
	h := &Handler{Roots: map[string]*Root{"public": root}, Resolver: resolver{rule}}
	get := func(path, rangeHeader string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if path == "/download/" {
			r.Header.Set("X-Trojan-Original-URI", "/downloads/")
		}
		if rangeHeader != "" {
			r.Header.Set("Range", rangeHeader)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := get("/download/report.txt", ""); w.Code != 200 || w.Body.String() != "public-data" || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatal("正常下载失败", w.Code, w.Body.String())
	}
	if w := get("/download/report.txt", "bytes=0-2"); w.Code != 206 || w.Body.String() != "pub" {
		t.Fatal("Range失败", w.Code, w.Body.String())
	}
	for _, path := range []string{"/download/../outside", "/download/%2e%2e/outside", "/download/.env", "/download/", "/missing/report.txt"} {
		if w := get(path, ""); w.Code != 404 || strings.Contains(w.Body.String(), "sentinel") {
			t.Fatalf("非法文件访问: %s %d", path, w.Code)
		}
	}
	rule.Browse = true
	h.Resolver = resolver{rule}
	if w := get("/download", ""); w.Code != 301 || w.Header().Get("Location") != "/downloads/" {
		t.Fatal("目录跳转暴露内部路由ID", w.Code, w.Header())
	}
	if w := get("/download/", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `href="./report.txt"`) || strings.Contains(w.Body.String(), ".env") {
		t.Fatal("目录索引错误", w.Code, w.Body.String())
	}
}

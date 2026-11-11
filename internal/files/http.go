package files

import (
	"context"
	"html/template"
	"mime"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
)

// Resolver 只能解析已提交的公开规则；待应用规则不能提前公开文件。
type Resolver interface {
	PublicRule(context.Context, string) (routes.Rule, error)
}

// Handler 仅在回环文件服务端口使用，根目录由部署配置显式授权。
type Handler struct {
	Roots    map[string]*Root
	Resolver Resolver
}

var directoryTemplate = template.Must(template.New("directory").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>公开下载目录</title><h1>公开下载目录</h1><p>此目录无需登录即可访问，文件以附件下载。</p><ul>{{range .}}<li><a href="{{.URL}}">{{.Name}}{{if .Directory}}/{{end}}</a></li>{{end}}</ul></html>`))

// ServeHTTP 提供GET/HEAD与Range下载；目录索引必须在规则中显式启用。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "仅支持只读下载", 405)
		return
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	rule, err := h.Resolver.PublicRule(r.Context(), parts[0])
	if err != nil || rule.Kind != "files" {
		http.NotFound(w, r)
		return
	}
	root := h.Roots[rule.DirectoryID]
	if root == nil {
		http.NotFound(w, r)
		return
	}
	name := "."
	if len(parts) == 2 && parts[1] != "" {
		name = strings.TrimSuffix(parts[1], "/")
	}
	file, err := root.Open(name)
	if err == nil {
		defer file.Close()
		stat, err := file.Stat()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(name)}))
		http.ServeContent(w, r, stat.Name(), stat.ModTime(), file)
		return
	}
	if !rule.Browse {
		http.NotFound(w, r)
		return
	}
	entries, err := root.List(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	publicPath := strings.TrimSuffix(rule.Path, "/") + "/"
	if name != "." {
		publicPath += name + "/"
	}
	originalPath := r.URL.Path
	if original := r.Header.Get("X-Trojan-Original-URI"); original != "" {
		if parsed, err := url.ParseRequestURI(original); err == nil {
			originalPath = parsed.Path
		}
	}
	if originalPath != publicPath {
		http.Redirect(w, r, (&url.URL{Path: publicPath}).String(), http.StatusMovedPermanently)
		return
	}
	type link struct {
		Name, URL string
		Directory bool
	}
	links := []link{}
	for _, entry := range entries {
		href := url.PathEscape(entry.Name)
		if entry.Directory {
			href += "/"
		}
		links = append(links, link{Name: entry.Name, URL: "./" + href, Directory: entry.Directory})
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Name < links[j].Name })
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == "HEAD" {
		return
	}
	directoryTemplate.Execute(w, links)
}

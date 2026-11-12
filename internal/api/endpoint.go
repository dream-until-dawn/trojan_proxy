package api

import (
	"context"
	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
	"net/http"
	"net/url"
	"path"
	"strings"
)

type endpointContextKey struct{}

func (s *Server) endpoints() []adminentry.Endpoint {
	if s.EndpointsProvider != nil {
		return s.EndpointsProvider()
	}
	origins := s.Origins
	if s.OriginProvider != nil {
		origins = s.OriginProvider()
	}
	result := make([]adminentry.Endpoint, 0, len(origins))
	for origin, allowed := range origins {
		if allowed {
			result = append(result, adminentry.Endpoint{Origin: origin})
		}
	}
	return result
}

func requestEndpoint(r *http.Request) string {
	if entry, ok := r.Context().Value(endpointContextKey{}).(string); ok {
		return entry
	}
	return r.Header.Get("Origin")
}

// withEndpointPolicy 用同一快照校验Host、路径及Origin，之后才剥离受信任前缀。
func (s *Server) withEndpointPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var selected *adminentry.Endpoint
		hostAllowed := false
		for _, entry := range s.endpoints() {
			origin, err := url.Parse(entry.Origin)
			if err != nil || origin.Host != r.Host {
				continue
			}
			hostAllowed = true
			matches := entry.Prefix == "" || r.URL.Path == entry.Prefix || strings.HasPrefix(r.URL.Path, entry.Prefix+"/")
			if matches && (selected == nil || len(entry.Prefix) > len(selected.Prefix)) {
				copy := entry
				selected = &copy
			}
		}
		if !hostAllowed {
			respond(w, 421, map[string]string{"error": "访问地址不被允许"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if selected == nil {
			respond(w, 404, map[string]string{"error": "管理路径不存在"})
			return
		}
		request := r.Clone(context.WithValue(r.Context(), endpointContextKey{}, selected.Identity()))
		if selected.Prefix != "" {
			if r.URL.RawPath != "" || strings.ContainsAny(r.URL.Path, "\\\x00") || path.Clean(r.URL.Path) != strings.TrimSuffix(r.URL.Path, "/") {
				respond(w, 404, map[string]string{"error": "管理路径无效"})
				return
			}
			if r.URL.Path == selected.Prefix {
				target := selected.Prefix + "/"
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusPermanentRedirect)
				return
			}
			request.URL.Path = strings.TrimPrefix(r.URL.Path, selected.Prefix)
			request.URL.RawPath = ""
		}
		if strings.HasPrefix(request.URL.Path, "/api/") && r.Header.Get("Origin") != selected.Origin {
			respond(w, 403, map[string]string{"error": "请求来源不被允许"})
			return
		}
		next.ServeHTTP(w, request)
	})
}

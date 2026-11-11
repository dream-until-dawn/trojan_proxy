// Package api 提供严格来源隔离的管理员HTTP接口。
package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
)

// Server 只信任配置来源，不根据Host或转发头动态扩大允许范围。
type Server struct {
	Auth    *auth.Service
	Origins map[string]bool
	Static  http.Handler
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

// Handler 为所有API统一加来源校验；静态资源不承载秘密。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]bool{"alive": true}) })
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/status", s.protected(func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]any{"authenticated": true, "scope": "认证底座已就绪，反代管理尚未接入"})
	}))
	mux.HandleFunc("POST /api/logout", s.protected(func(w http.ResponseWriter, r *http.Request) {
		s.Auth.Logout(bearer(r))
		respond(w, 200, map[string]bool{"ok": true})
	}))
	if s.Static != nil {
		mux.Handle("/", s.Static)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hostAllowed := false
		for origin := range s.Origins {
			u, err := url.Parse(origin)
			if err == nil && u.Host == r.Host {
				hostAllowed = true
				break
			}
		}
		if !hostAllowed {
			respond(w, 421, map[string]string{"error": "访问地址不被允许"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.Origins[r.Header.Get("Origin")] {
			respond(w, 403, map[string]string{"error": "请求来源不被允许"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func bearer(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(header, "Bearer ")
}

func (s *Server) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.Auth.Validate(bearer(r)) {
			respond(w, 401, map[string]string{"error": "请重新登录"})
			return
		}
		next(w, r)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		respond(w, 415, map[string]string{"error": "请使用JSON请求"})
		return
	}
	var input struct {
		Password string `json:"password"`
		OTP      string `json:"otp"`
		Recovery string `json:"recovery"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		respond(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		respond(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	token, err := s.Auth.Login(r.Context(), input.Password, input.OTP, input.Recovery)
	if err != nil {
		status := 401
		if errors.Is(err, auth.ErrLimited) {
			status = 429
			w.Header().Set("Retry-After", "60")
		}
		if errors.Is(err, auth.ErrUnavailable) {
			status = 503
		}
		respond(w, status, map[string]string{"error": err.Error()})
		return
	}
	respond(w, 200, map[string]string{"token": token})
}

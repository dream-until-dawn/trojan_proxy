// Package api 提供严格来源隔离的管理员HTTP接口。
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	"github.com/dream-until-dawn/trojan_proxy/internal/routing"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/traffic"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpnservice"
)

// Authentication 允许独立验证权限边界，生产实现必须同时支持会话与近期MFA校验。
type Authentication interface {
	Login(context.Context, string, string, string) (string, error)
	Validate(string) bool
	Recent(string) bool
	Logout(string)
}

// VPNManagement 让HTTP权限测试独立于真实子进程；生产实现使用vpnservice.Service。
type VPNManagement interface {
	Status(context.Context) (vpnservice.Status, error)
	Apply(context.Context, uint64, bool, bool) error
	Export(context.Context) ([]byte, error)
}

// SettingsManagement 不向HTTP层暴露回滚JSON和加密VPN配置。
type SettingsManagement interface {
	Status(context.Context) (settings.Snapshot, error)
	Propose(context.Context, uint64, settings.Site) error
	Confirm(context.Context, uint64, string) error
	Cancel(context.Context, uint64) error
}

type TrafficManagement interface {
	State() traffic.Live
	Dashboard(context.Context, int, int) (traffic.Dashboard, error)
	Clear(context.Context) error
}

type CertificateManagement interface {
	Status(context.Context) (certificates.State, error)
	Import(string, []byte, []byte) (certificates.Prepared, error)
}

// Server 只信任配置来源，不根据Host或转发头动态扩大允许范围。
type Server struct {
	Auth           Authentication
	Origins        map[string]bool
	Static         http.Handler
	Routes         *routing.Service
	VPN            VPNManagement
	Settings       SettingsManagement
	OriginProvider func() map[string]bool
	WriteGuard     func(context.Context) error
	Traffic        TrafficManagement
	Certificates   CertificateManagement
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
		respond(w, 200, map[string]any{"authenticated": true, "scope": "认证正常。业务规则按修订校验、应用；修改需最近五分钟内的双因素登录。"})
	}))
	mux.HandleFunc("POST /api/logout", s.protected(func(w http.ResponseWriter, r *http.Request) {
		s.Auth.Logout(bearer(r))
		respond(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/routes/list", s.protected(s.listRoutes))
	mux.HandleFunc("POST /api/routes/apply", s.protected(s.applyRoutes))
	mux.HandleFunc("POST /api/vpn/status", s.protected(s.vpnStatus))
	mux.HandleFunc("POST /api/vpn/apply", s.protected(s.vpnApply))
	mux.HandleFunc("POST /api/vpn/export", s.protected(s.vpnExport))
	mux.HandleFunc("POST /api/settings/status", s.protected(s.settingsStatus))
	mux.HandleFunc("POST /api/settings/propose", s.protected(s.settingsPropose))
	mux.HandleFunc("POST /api/settings/confirm", s.protected(s.settingsConfirm))
	mux.HandleFunc("POST /api/settings/cancel", s.protected(s.settingsCancel))
	mux.HandleFunc("POST /api/traffic/live", s.protected(s.trafficLive))
	mux.HandleFunc("POST /api/traffic/dashboard", s.protected(s.trafficDashboard))
	mux.HandleFunc("POST /api/traffic/clear", s.protected(s.trafficClear))
	mux.HandleFunc("POST /api/certificates/status", s.protected(s.certificateStatus))
	mux.HandleFunc("POST /api/certificates/import", s.protected(s.certificateImport))
	if s.Static != nil {
		mux.Handle("/", s.Static)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origins := s.Origins
		if s.OriginProvider != nil {
			origins = s.OriginProvider()
		}
		hostAllowed := false
		for origin := range origins {
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
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") && !origins[r.Header.Get("Origin")] {
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
		valid := false
		if passive, ok := s.Auth.(interface{ ValidatePassive(string) bool }); ok && r.URL.Path == "/api/traffic/live" {
			valid = passive.ValidatePassive(bearer(r))
		} else {
			valid = s.Auth.Validate(bearer(r))
		}
		if !valid {
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

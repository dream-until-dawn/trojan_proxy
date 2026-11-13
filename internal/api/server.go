// Package api 提供严格来源隔离的管理员HTTP接口。
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/adminentry"
	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/certificates"
	"github.com/dream-until-dawn/trojan_proxy/internal/routing"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/traffic"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpnservice"
	"github.com/dream-until-dawn/trojan_proxy/internal/webaccess"
)

// Authentication 允许独立验证权限边界，生产实现必须支持绑定入口的会话与近期MFA校验。
type Authentication interface {
	LoginAt(context.Context, string, string, string, string) (string, error)
	ValidateAt(string, string, bool) bool
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

// WebAccessManagement 与VPN统计完全隔离，仅管理员可读取或调整保留分类。
type WebAccessManagement interface {
	State() webaccess.State
	Policy(context.Context) (webaccess.Policy, error)
	SetWhitelist(context.Context, uint64, []string) error
	Dashboard(context.Context, webaccess.Filter) (webaccess.Dashboard, error)
}

// Server 只信任配置来源，不根据Host或转发头动态扩大允许范围。
type Server struct {
	Auth              Authentication
	Origins           map[string]bool
	Static            http.Handler
	Routes            *routing.Service
	VPN               VPNManagement
	Settings          SettingsManagement
	OriginProvider    func() map[string]bool
	EndpointsProvider func() []adminentry.Endpoint
	WriteGuard        func(context.Context) error
	Traffic           TrafficManagement
	Certificates      CertificateManagement
	WebAccess         WebAccessManagement
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
	mux.HandleFunc("POST /api/access/status", s.protected(s.accessStatus))
	mux.HandleFunc("POST /api/access/dashboard", s.protected(s.accessDashboard))
	mux.HandleFunc("POST /api/access/policy", s.protected(s.accessPolicy))
	mux.HandleFunc("POST /api/access/policy/apply", s.protected(s.accessApply))
	mux.HandleFunc("POST /api/certificates/status", s.protected(s.certificateStatus))
	mux.HandleFunc("POST /api/certificates/import", s.protected(s.certificateImport))
	if s.Static != nil {
		mux.Handle("/", s.Static)
	}
	return s.withEndpointPolicy(mux)
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
		valid := s.Auth.ValidateAt(bearer(r), requestEndpoint(r), r.URL.Path == "/api/traffic/live")
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
	token, err := s.Auth.LoginAt(r.Context(), input.Password, input.OTP, input.Recovery, requestEndpoint(r))
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

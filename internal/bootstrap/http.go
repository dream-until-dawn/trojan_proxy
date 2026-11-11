package bootstrap

import (
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
)

//go:embed assets/*
var assets embed.FS

// Handler 只允许固定本机来源；必须挂载于专用loopback监听而非公网网关上游。
func (s *Service) Handler(port int, completed func()) http.Handler {
	origins := map[string]bool{
		"http://127.0.0.1:" + strconv.Itoa(port): true,
		"http://localhost:" + strconv.Itoa(port): true,
	}
	sub, _ := fs.Sub(assets, "assets")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]string{"status": "setup_pending"})
	})
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("POST /api/setup/begin", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Token    string `json:"token"`
			Password string `json:"password"`
		}
		if !decode(w, r, &input) {
			return
		}
		result, err := s.Begin(r.Context(), input.Token, input.Password)
		if err != nil {
			reply(w, 400, map[string]string{"error": "令牌无效、已使用或口令不符合要求（16至1024字节），请从本机重新获取令牌"})
			return
		}
		reply(w, 200, result)
	})
	mux.HandleFunc("POST /api/setup/finish", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Session string `json:"session"`
			OTP     string `json:"otp"`
			Saved   bool   `json:"saved"`
		}
		if !decode(w, r, &input) {
			return
		}
		if err := s.Finish(r.Context(), input.Session, input.OTP, input.Saved); err != nil {
			reply(w, 400, map[string]string{"error": "绑定未完成：请确认恢复码已保存并输入当前验证码；过期或多次失败请从本机重新开始"})
			return
		}
		reply(w, 200, map[string]any{"ok": true, "login_url": "http://127.0.0.1:" + strconv.Itoa(port-2)})
		if completed != nil {
			completed()
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		remote, _, err := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(remote)
		if err != nil || ip == nil || !ip.IsLoopback() || !origins["http://"+r.Host] || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Forwarded-Host") != "" {
			reply(w, 403, map[string]string{"error": "初始化仅允许本机SSH隧道访问"})
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && (!origins[r.Header.Get("Origin")] || r.Header.Get("Origin") != "http://"+r.Host) {
			reply(w, 403, map[string]string{"error": "请求来源不被允许"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		reply(w, 415, map[string]string{"error": "请使用JSON请求"})
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		reply(w, 400, map[string]string{"error": "请求格式错误"})
		return false
	}
	return true
}

func reply(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

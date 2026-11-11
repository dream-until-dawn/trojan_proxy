package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

func (s *Server) vpnStatus(w http.ResponseWriter, r *http.Request) {
	if s.VPN == nil {
		respond(w, 200, map[string]any{"available": false, "message": "VPN管理尚未启用"})
		return
	}
	state, err := s.VPN.Status(r.Context())
	if err != nil {
		respond(w, 503, map[string]string{"error": "VPN状态暂时不可读"})
		return
	}
	respond(w, 200, state)
}

func (s *Server) vpnApply(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.Recent(bearer(r)) {
		respond(w, 403, map[string]string{"error": "启停或轮换VPN需要最近五分钟内的双因素登录，请重新登录"})
		return
	}
	if s.VPN == nil {
		respond(w, 503, map[string]string{"error": "VPN管理尚未启用"})
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		respond(w, 415, map[string]string{"error": "请使用JSON请求"})
		return
	}
	var input struct {
		Revision uint64 `json:"revision"`
		Enabled  bool   `json:"enabled"`
		Rotate   bool   `json:"rotate"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		respond(w, 400, map[string]string{"error": "VPN请求格式错误"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF || (!input.Enabled && input.Rotate) {
		respond(w, 400, map[string]string{"error": "VPN请求格式错误"})
		return
	}
	if err := s.VPN.Apply(r.Context(), input.Revision, input.Enabled, input.Rotate); err != nil {
		if errors.Is(err, control.ErrRevisionConflict) {
			respond(w, 409, map[string]string{"error": "修订已变化，请刷新后重试"})
			return
		}
		respond(w, 503, map[string]string{"error": "VPN未能生效，请核实证书与执行器状态，再刷新确认实际结果"})
		return
	}
	respond(w, 200, map[string]bool{"applied": true})
}

func (s *Server) vpnExport(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.Recent(bearer(r)) {
		respond(w, 403, map[string]string{"error": "下载含口令的配置需要最近五分钟内的双因素登录，请重新登录"})
		return
	}
	if s.VPN == nil {
		respond(w, 503, map[string]string{"error": "VPN管理尚未启用"})
		return
	}
	body, err := s.VPN.Export(r.Context())
	if err != nil {
		respond(w, 503, map[string]string{"error": "VPN实际运行或证书未就绪，暂不可导出"})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="trojan-clash.yaml"`)
	w.WriteHeader(200)
	w.Write(body)
}

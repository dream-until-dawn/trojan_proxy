package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/dream-until-dawn/trojan_proxy/internal/routes"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
)

func (s *Server) listRoutes(w http.ResponseWriter, r *http.Request) {
	if s.Routes == nil {
		respond(w, 503, map[string]string{"error": "反代管理尚未连接网关"})
		return
	}
	state, err := s.Routes.List(r.Context())
	if err != nil {
		respond(w, 503, map[string]string{"error": "网关未就绪或修订需要恢复"})
		return
	}
	respond(w, 200, state)
}

func (s *Server) applyRoutes(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.Recent(bearer(r)) {
		respond(w, 403, map[string]string{"error": "修改公开路由需要最近五分钟内的双因素登录，请重新登录"})
		return
	}
	if s.Routes == nil {
		respond(w, 503, map[string]string{"error": "反代管理尚未连接网关"})
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		respond(w, 415, map[string]string{"error": "请使用JSON请求"})
		return
	}
	var input struct {
		Revision uint64        `json:"revision"`
		Rules    []routes.Rule `json:"rules"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		respond(w, 400, map[string]string{"error": "路由请求格式错误"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		respond(w, 400, map[string]string{"error": "路由请求格式错误"})
		return
	}
	if err := s.Routes.Apply(r.Context(), input.Revision, input.Rules); err != nil {
		status := 503
		message := "网关应用或恢复未完成，请刷新核实实际状态；状态异常时暂停修改"
		var invalid *routes.ValidationError
		if errors.As(err, &invalid) {
			status = 400
			message = invalid.Error()
		}
		if errors.Is(err, control.ErrRevisionConflict) {
			status = 409
			message = "修订已变化，请刷新后重新确认草稿"
		}
		respond(w, status, map[string]string{"error": message})
		return
	}
	respond(w, 200, map[string]bool{"applied": true})
}

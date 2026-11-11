package api

import (
	"context"
	"net/http"
	"time"
)

func (s *Server) trafficLive(w http.ResponseWriter, r *http.Request) {
	if s.Traffic == nil {
		respond(w, 200, map[string]any{"available": false, "message": "统计尚未连接"})
		return
	}
	respond(w, 200, s.Traffic.State())
}

func (s *Server) trafficDashboard(w http.ResponseWriter, r *http.Request) {
	if s.Traffic == nil {
		respond(w, 503, map[string]string{"error": "统计尚未连接"})
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		respond(w, 415, map[string]string{"error": "请使用JSON请求"})
		return
	}
	var input struct {
		Hours  int `json:"hours"`
		Offset int `json:"offset"`
	}
	if !settingsDecode(w, r, &input) {
		return
	}
	if input.Hours < 1 || input.Hours > 720 || input.Offset < 0 || input.Offset > 10000 {
		respond(w, 400, map[string]string{"error": "请选择1至720小时及有效分页范围"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	dashboard, err := s.Traffic.Dashboard(ctx, input.Hours, input.Offset)
	if err != nil {
		respond(w, 503, map[string]string{"error": "统计暂不可用；代理和认证服务不依赖统计库"})
		return
	}
	respond(w, 200, dashboard)
}

func (s *Server) trafficClear(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.Recent(bearer(r)) {
		respond(w, 403, map[string]string{"error": "清空统计需要最近五分钟内的双因素登录"})
		return
	}
	if s.Traffic == nil {
		respond(w, 503, map[string]string{"error": "统计尚未连接"})
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		respond(w, 415, map[string]string{"error": "请使用JSON请求"})
		return
	}
	var input struct {
		Confirm bool `json:"confirm"`
	}
	if !settingsDecode(w, r, &input) {
		return
	}
	if !input.Confirm {
		respond(w, 400, map[string]string{"error": "请确认永久清空统计记录"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if s.Traffic.Clear(ctx) != nil {
		respond(w, 503, map[string]string{"error": "清空或空间清理未完成，请刷新核实"})
		return
	}
	respond(w, 200, map[string]string{"message": "历史已清空，下一分钟恢复保存；实时采样继续"})
}

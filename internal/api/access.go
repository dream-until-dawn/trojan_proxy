package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/webaccess"
)

func (s *Server) accessReady(w http.ResponseWriter) bool {
	if s.WebAccess == nil {
		respond(w, 503, map[string]string{"error": "网站访问记录尚未连接"})
		return false
	}
	return true
}
func (s *Server) accessStatus(w http.ResponseWriter, r *http.Request) {
	if s.accessReady(w) {
		respond(w, 200, s.WebAccess.State())
	}
}
func (s *Server) accessPolicy(w http.ResponseWriter, r *http.Request) {
	if !s.accessReady(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	policy, err := s.WebAccess.Policy(ctx)
	if err != nil {
		accessUnavailable(w)
		return
	}
	respond(w, 200, policy)
}
func accessUnavailable(w http.ResponseWriter) {
	respond(w, 503, map[string]string{"error": "网站访问记录暂不可用，请检查采集状态；认证和代理继续运行"})
}
func accessJSON(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		respond(w, 415, map[string]string{"error": "请使用JSON请求"})
		return false
	}
	return true
}
func (s *Server) accessDashboard(w http.ResponseWriter, r *http.Request) {
	if !s.accessReady(w) || !accessJSON(w, r) {
		return
	}
	var input webaccess.Filter
	if !settingsDecode(w, r, &input) {
		return
	}
	if err := webaccess.ValidateFilter(input); err != nil {
		respond(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	dashboard, err := s.WebAccess.Dashboard(ctx, input)
	if err != nil {
		accessUnavailable(w)
		return
	}
	respond(w, 200, dashboard)
}
func (s *Server) accessApply(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.Recent(bearer(r)) {
		respond(w, 403, map[string]string{"error": "修改访问白名单需要最近五分钟内的双因素登录"})
		return
	}
	if !s.accessReady(w) || !accessJSON(w, r) {
		return
	}
	var input struct {
		Revision uint64   `json:"revision"`
		CIDRs    []string `json:"cidrs"`
		Confirm  bool     `json:"confirm"`
	}
	if !settingsDecode(w, r, &input) {
		return
	}
	if !input.Confirm || input.Revision == 0 {
		respond(w, 400, map[string]string{"error": "请确认按当前白名单重新分类并立即清理到期历史"})
		return
	}
	normalized, err := webaccess.NormalizeWhitelist(input.CIDRs)
	if err != nil {
		respond(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	err = s.WebAccess.SetWhitelist(ctx, input.Revision, normalized)
	if errors.Is(err, webaccess.ErrRevision) {
		respond(w, 409, map[string]string{"error": err.Error()})
		return
	}
	if err != nil {
		accessUnavailable(w)
		return
	}
	respond(w, 200, map[string]string{"message": "白名单已更新；历史按当前名单分类，到期记录已清理"})
}

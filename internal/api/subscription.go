package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/subscription"
	"github.com/dream-until-dawn/trojan_proxy/internal/vpn"
)

func (s *Server) subscriptionError(w http.ResponseWriter, err error) {
	status := 503
	message := "订阅服务或VPN暂不可用"
	switch {
	case errors.Is(err, subscription.ErrDenied):
		status = 404
		message = "订阅不存在或已失效"
	case errors.Is(err, subscription.ErrLimit):
		status = 429
		message = "订阅数量或并发已达上限"
		w.Header().Set("Retry-After", "30")
	case errors.Is(err, subscription.ErrName):
		status = 400
		message = "设备名称须为1至40个可见字符"
	}
	respond(w, status, map[string]string{"error": message})
}

func (s *Server) subscriptionList(w http.ResponseWriter, r *http.Request) {
	if s.Subscriptions == nil {
		s.subscriptionError(w, subscription.ErrUnavailable)
		return
	}
	records, err := s.Subscriptions.List(r.Context())
	if err != nil {
		s.subscriptionError(w, err)
		return
	}
	respond(w, 200, map[string]any{"items": records})
}

func (s *Server) subscriptionInput(w http.ResponseWriter, r *http.Request, value any) bool {
	if !s.Auth.Recent(bearer(r)) {
		respond(w, 403, map[string]string{"error": "管理订阅需要最近五分钟内的双因素登录"})
		return false
	}
	if !s.businessWriteAllowed(w, r) {
		return false
	}
	if s.Subscriptions == nil {
		s.subscriptionError(w, subscription.ErrUnavailable)
		return false
	}
	if r.Header.Get("Content-Type") != "application/json" {
		respond(w, 415, map[string]string{"error": "请使用JSON请求"})
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		respond(w, 400, map[string]string{"error": "订阅请求格式错误"})
		return false
	}
	return true
}

func (s *Server) subscriptionCreate(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name string `json:"name"`
	}
	if !s.subscriptionInput(w, r, &input) {
		return
	}
	endpoint := requestEndpoint(r)
	if !strings.HasPrefix(endpoint, "https://") {
		respond(w, 403, map[string]string{"error": "请从HTTPS后台创建订阅链接"})
		return
	}
	record, token, err := s.Subscriptions.Create(r.Context(), input.Name)
	if err != nil {
		s.subscriptionError(w, err)
		return
	}
	link := endpoint + "/subscription/clash?" + url.Values{"token": []string{token}}.Encode()
	respond(w, 200, map[string]any{"item": record, "url": link})
}

func (s *Server) subscriptionRevoke(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ID string `json:"id"`
	}
	if !s.subscriptionInput(w, r, &input) {
		return
	}
	if len(input.ID) != 22 {
		respond(w, 400, map[string]string{"error": "订阅编号无效"})
		return
	}
	if err := s.Subscriptions.Revoke(r.Context(), input.ID); err != nil {
		s.subscriptionError(w, err)
		return
	}
	respond(w, 200, map[string]bool{"revoked": true})
}

// subscriptionFetch 是刻意独立的只读授权入口，不签发后台会话，不接受自选目标。
func (s *Server) subscriptionFetch(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(requestEndpoint(r), "https://") {
		respond(w, 403, map[string]string{"error": "订阅仅通过HTTPS提供"})
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		allowed := false
		for _, e := range s.endpoints() {
			if e.Identity() == requestEndpoint(r) && e.Origin == origin {
				allowed = true
			}
		}
		if !allowed {
			respond(w, 403, map[string]string{"error": "请求来源不被允许"})
			return
		}
	}
	if len(r.URL.RawQuery) > 1024 {
		s.subscriptionError(w, subscription.ErrDenied)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["token"]) != 1 {
		s.subscriptionError(w, subscription.ErrDenied)
		return
	}
	if s.Subscriptions == nil {
		s.subscriptionError(w, subscription.ErrUnavailable)
		return
	}
	body, err := s.Subscriptions.Fetch(r.Context(), query.Get("token"))
	if err != nil {
		s.subscriptionError(w, err)
		return
	}
	// 订阅域通常是后台子域，与Trojan节点域不同，不能只直连节点域。
	endpoint, err := url.Parse(requestEndpoint(r))
	if err != nil {
		s.subscriptionError(w, subscription.ErrUnavailable)
		return
	}
	body, err = vpn.WithSubscriptionDirect(body, endpoint.Hostname())
	if err != nil {
		s.subscriptionError(w, subscription.ErrUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="trojan-clash.yaml"`)
	w.WriteHeader(200)
	w.Write(body)
}

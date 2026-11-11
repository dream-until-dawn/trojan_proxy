package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
)

func (s *Server) settingsStatus(w http.ResponseWriter, r *http.Request) {
	if s.Settings == nil {
		respond(w, 200, map[string]bool{"available": false})
		return
	}
	snapshot, err := s.Settings.Status(r.Context())
	if err != nil {
		settingsError(w, err)
		return
	}
	respond(w, 200, map[string]any{"available": true, "settings": snapshot})
}

func (s *Server) settingsWrite(w http.ResponseWriter, r *http.Request) bool {
	if !s.Auth.Recent(bearer(r)) {
		respond(w, 403, map[string]string{"error": "修改后台入口需要最近五分钟内的双因素登录，请重新登录"})
		return false
	}
	if s.Settings == nil {
		respond(w, 503, map[string]string{"error": "设置管理尚未连接"})
		return false
	}
	if r.Header.Get("Content-Type") != "application/json" {
		respond(w, 415, map[string]string{"error": "请使用JSON请求"})
		return false
	}
	return true
}

func settingsDecode(w http.ResponseWriter, r *http.Request, input any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	decoder.DisallowUnknownFields()
	if decoder.Decode(input) != nil || decoder.Decode(new(any)) != io.EOF {
		respond(w, 400, map[string]string{"error": "设置请求格式错误"})
		return false
	}
	return true
}

func (s *Server) settingsPropose(w http.ResponseWriter, r *http.Request) {
	if !s.settingsWrite(w, r) {
		return
	}
	var input struct {
		Revision uint64        `json:"revision"`
		Site     settings.Site `json:"site"`
	}
	if !settingsDecode(w, r, &input) {
		return
	}
	if err := s.Settings.Propose(r.Context(), input.Revision, input.Site); err != nil {
		settingsError(w, err)
		return
	}
	respond(w, 200, map[string]bool{"pending": true})
}

func (s *Server) settingsConfirm(w http.ResponseWriter, r *http.Request) {
	if !s.settingsWrite(w, r) {
		return
	}
	var input struct {
		Revision uint64 `json:"revision"`
	}
	if !settingsDecode(w, r, &input) {
		return
	}
	origin := r.Header.Get("Origin")
	source, err := url.Parse(origin)
	if err != nil || source.Host != r.Host {
		respond(w, 403, map[string]string{"error": "请直接打开新后台入口并登录确认"})
		return
	}
	if err = s.Settings.Confirm(r.Context(), input.Revision, origin); err != nil {
		settingsError(w, err)
		return
	}
	respond(w, 200, map[string]bool{"confirmed": true})
}

func (s *Server) settingsCancel(w http.ResponseWriter, r *http.Request) {
	if !s.settingsWrite(w, r) {
		return
	}
	var input struct {
		Revision uint64 `json:"revision"`
	}
	if !settingsDecode(w, r, &input) {
		return
	}
	if err := s.Settings.Cancel(r.Context(), input.Revision); err != nil {
		settingsError(w, err)
		return
	}
	respond(w, 200, map[string]bool{"cancelled": true})
}

func settingsError(w http.ResponseWriter, err error) {
	status := 503
	message := "入口配置未能生效，请刷新状态；旧入口和SSH恢复通道仍应保留"
	var invalid *settings.ValidationError
	switch {
	case errors.As(err, &invalid):
		status = 400
		message = invalid.Error()
	case errors.Is(err, control.ErrRevisionConflict):
		status = 409
		message = "修订已变化，请刷新后重试"
	case errors.Is(err, settings.ErrFrozen):
		status = 423
		message = "已有入口等待确认，请先确认或撤回"
	case errors.Is(err, settings.ErrConfirmation):
		status = 409
		message = "新入口、证书或确认期限不符合条件，请刷新状态"
	}
	respond(w, status, map[string]string{"error": message})
}

// businessWriteAllowed 同时覆盖反代及VPN写入；读取、登录和恢复操作不被冻结。
func (s *Server) businessWriteAllowed(w http.ResponseWriter, r *http.Request) bool {
	if s.WriteGuard != nil {
		if err := s.WriteGuard(r.Context()); err != nil {
			settingsError(w, err)
			return false
		}
	}
	return true
}

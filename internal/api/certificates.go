package api

import (
	"encoding/json"
	"io"
	"net/http"
)

func (s *Server) certificateStatus(w http.ResponseWriter, r *http.Request) {
	if s.Certificates == nil {
		respond(w, 200, map[string]bool{"available": false})
		return
	}
	state, err := s.Certificates.Status(r.Context())
	if err != nil {
		respond(w, 503, map[string]string{"error": "证书状态暂不可用"})
		return
	}
	respond(w, 200, state)
}

// 上传只生成不可变版本；激活须通过业务设置修订和入口确认。
func (s *Server) certificateImport(w http.ResponseWriter, r *http.Request) {
	if !s.Auth.Recent(bearer(r)) {
		respond(w, 403, map[string]string{"error": "导入证书需要最近五分钟内的双因素登录"})
		return
	}
	if s.Certificates == nil {
		respond(w, 503, map[string]string{"error": "证书管理尚未连接"})
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		respond(w, 415, map[string]string{"error": "请使用JSON请求"})
		return
	}
	var input struct {
		Domain string `json:"domain"`
		Chain  string `json:"certificate"`
		Key    string `json:"private_key"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*1024*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.Domain == "" || len(input.Chain) > 1024*1024 || len(input.Key) > 65536 {
		respond(w, 400, map[string]string{"error": "证书请求格式或大小不符合要求"})
		return
	}
	prepared, err := s.Certificates.Import(input.Domain, []byte(input.Chain), []byte(input.Key))
	if err != nil {
		respond(w, 400, map[string]string{"error": "导入失败，请核对域名、可信链、有效期、私钥配对及发布空间"})
		return
	}
	respond(w, 200, prepared)
}

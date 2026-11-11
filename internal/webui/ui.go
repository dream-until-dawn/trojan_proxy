// Package webui 将中文管理界面嵌入镜像，无运行时CDN或远程脚本依赖。
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed assets/*
var assets embed.FS

// Handler 返回只读的界面资源处理器。
func Handler() http.Handler { sub, _ := fs.Sub(assets, "assets"); return http.FileServer(http.FS(sub)) }

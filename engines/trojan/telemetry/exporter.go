// SPDX-License-Identifier: GPL-3.0-or-later
package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Exporter 仅在调用者提供的私有listener上暴露只读快照，不包含控制或配置API。
type Exporter struct {
	server *http.Server
	stop   chan struct{}
	done   chan struct{}
	once   sync.Once
}

// Serve 启动固定2秒采样；listener必须由Unix权限边界创建，不能直接绑定公网。
func Serve(listener net.Listener, sampler *Sampler) (*Exporter, error) {
	if listener.Addr().Network() != "unix" {
		return nil, errors.New("统计接口只能使用Unix socket")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /snapshot", func(w http.ResponseWriter, r *http.Request) {
		after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
		if err != nil || after < 0 || len(r.URL.Query().Get("instance")) > 64 {
			http.Error(w, "invalid cursor", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(sampler.Snapshot(r.URL.Query().Get("instance"), after))
	})
	exporter := &Exporter{server: &http.Server{Handler: mux, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 2048}, stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		defer close(exporter.done)
		for {
			select {
			case <-ticker.C:
				sampler.Flush()
			case <-exporter.stop:
				return
			}
		}
	}()
	go func() { exporter.server.Serve(listener) }()
	return exporter, nil
}

// Close 不写IP明细到持久化临时文件；最后一个未采集窗口作为重启缺口处理。
func (e *Exporter) Close() error {
	e.once.Do(func() { close(e.stop) })
	<-e.done
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := e.server.Shutdown(ctx)
	if err != nil {
		e.server.Close()
	}
	return err
}

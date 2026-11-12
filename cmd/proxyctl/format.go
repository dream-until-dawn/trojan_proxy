package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/maintenance"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
	"os"
	"path/filepath"
	"time"
)

// downgradeHTTPFormat 不提供路由写入后门；仅在control停止后验证旧镜像的兼容前提。
func downgradeHTTPFormat(path string) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	lock, err := maintenance.Acquire(c.DataDir, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if _, err = os.Stat(filepath.Join(c.DataDir, "control.db")); err != nil {
		return errors.New("现有数据库不存在，拒绝初始化")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := storage.OpenJournal(ctx, filepath.Join(c.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		return err
	}
	defer store.Close()
	version, err := store.DowngradeHTTPFormat(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"format": version, "business_and_credentials_unchanged": true})
}

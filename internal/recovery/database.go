package recovery

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/auth"
	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/settings"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

func validateDatabase(ctx context.Context, path string, key []byte, deployment config.Config) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	q := u.Query()
	q.Set("mode", "ro")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return err
	}
	defer db.Close()
	var version int
	var integrity string
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version < 2 || version > 6 {
		return errors.New("备份数据库版本不受支持")
	}
	if err = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("备份数据库完整性检查失败")
	}
	var raw string
	if err = db.QueryRowContext(ctx, "SELECT body FROM revision_journal WHERE id=1").Scan(&raw); err != nil {
		return errors.New("备份缺少完整配置修订")
	}
	var journal control.Journal
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || journal.Applied.Number < 1 {
		return errors.New("备份配置修订无效")
	}
	required, err := storage.RequiredJournalVersion(journal)
	if err != nil || version < required {
		return errors.New("备份格式版本不足以保护HTTPS规则")
	}
	if journal.Applied.Settings != "" {
		if _, err = settings.Decode(journal.Applied.Settings, deployment); err != nil {
			return errors.New("备份业务设置与部署边界不兼容")
		}
	}
	var secret []byte
	if err = db.QueryRowContext(ctx, "SELECT secret FROM administrator WHERE id=1").Scan(&secret); err != nil {
		return errors.New("备份缺少已绑定管理员")
	}
	if _, err = auth.DecryptSecret(key, secret); err != nil {
		return errors.New("备份主密钥与认证库不匹配")
	}
	return nil
}

// Package recovery 处理私有一致性备份与空目录冷还原，不提供公网入口。
package recovery

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/maintenance"
	control "github.com/dream-until-dawn/trojan_proxy/internal/runtime"
	"github.com/dream-until-dawn/trojan_proxy/internal/storage"
)

const maxDB = 64 << 20
const maxArchive = 72 << 20

var fileLimits = map[string]int64{"control.db": maxDB, "master.key": 32, "deployment.json": 1 << 20, "manifest.json": 65536}

type manifest struct {
	Version int               `json:"version"`
	Created string            `json:"created_utc"`
	Files   map[string]string `json:"files"`
}

// Report 只包含摘要、位置和大小，不能包含归档内秘密。
type Report struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

func readKey(directory string) ([]byte, error) {
	path := filepath.Join(directory, "master.key")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("主密钥不存在或不是普通文件")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	key, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(key) != 32 {
		return nil, errors.New("主密钥无效，拒绝重新生成")
	}
	return key, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func cleanTemporary(directory, parent, prefix string) {
	// 清理仅限本次创建的直接临时子目录，绝不递归删除数据卷或用户指定的归档目录。
	if filepath.Dir(directory) == parent && strings.HasPrefix(filepath.Base(directory), prefix) {
		os.RemoveAll(directory)
	}
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// Backup 允许控制进程在线，SQLite负责一致性；维护独占操作会被同卷锁拒绝。
func Backup(ctx context.Context, c config.Config, output string) (report Report, err error) {
	lock, err := maintenance.Acquire(c.DataDir, false)
	if err != nil {
		return report, err
	}
	defer lock.Close()
	key, err := readKey(c.DataDir)
	if err != nil {
		return report, err
	}
	defer clear(key)
	if info, err := os.Lstat(filepath.Join(c.DataDir, "control.db")); err != nil || !info.Mode().IsRegular() {
		return report, errors.New("认证数据库不存在或不是普通文件")
	}
	abs, err := filepath.Abs(output)
	if err != nil {
		return report, err
	}
	for _, root := range c.PublicDirectories {
		public, err := filepath.Abs(root)
		if err != nil {
			return report, err
		}
		rel, err := filepath.Rel(public, abs)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return report, errors.New("备份不能写入公开目录")
		}
	}
	parent := filepath.Dir(abs)
	if err = os.MkdirAll(parent, 0700); err != nil {
		return report, err
	}
	temp, err := os.MkdirTemp(parent, ".backup-")
	if err != nil {
		return report, err
	}
	defer cleanTemporary(temp, parent, ".backup-")
	db, err := storage.OpenJournal(ctx, filepath.Join(c.DataDir, "control.db"), control.Revision{Number: 1})
	if err != nil {
		return report, err
	}
	err = db.BackupInto(ctx, filepath.Join(temp, "control.db"))
	db.Close()
	if err != nil {
		return report, err
	}
	if err = validateDatabase(ctx, filepath.Join(temp, "control.db"), key, c); err != nil {
		return report, err
	}
	if err = os.WriteFile(filepath.Join(temp, "master.key"), key, 0600); err != nil {
		return report, err
	}
	body, err := json.Marshal(c)
	if err != nil {
		return report, err
	}
	if err = os.WriteFile(filepath.Join(temp, "deployment.json"), body, 0600); err != nil {
		return report, err
	}
	m := manifest{Version: 1, Created: time.Now().UTC().Format(time.RFC3339), Files: map[string]string{}}
	for _, name := range []string{"control.db", "master.key", "deployment.json"} {
		m.Files[name], err = hashFile(filepath.Join(temp, name))
		if err != nil {
			return report, err
		}
	}
	body, err = json.Marshal(m)
	if err != nil {
		return report, err
	}
	if err = os.WriteFile(filepath.Join(temp, "manifest.json"), body, 0600); err != nil {
		return report, err
	}
	out, err := os.OpenFile(abs, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return report, err
	}
	defer func() {
		out.Close()
		if err != nil {
			os.Remove(abs)
		}
	}()
	h := sha256.New()
	zipper := gzip.NewWriter(io.MultiWriter(out, h))
	archive := tar.NewWriter(zipper)
	for _, name := range []string{"manifest.json", "control.db", "master.key", "deployment.json"} {
		path := filepath.Join(temp, name)
		info, statErr := os.Stat(path)
		if statErr != nil {
			err = statErr
			return report, err
		}
		if info.Size() > fileLimits[name] {
			err = errors.New("备份条目超过大小预算")
			return report, err
		}
		if err = archive.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: info.Size(), Typeflag: tar.TypeReg}); err != nil {
			return report, err
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			err = openErr
			return report, err
		}
		_, err = io.Copy(archive, file)
		file.Close()
		if err != nil {
			return report, err
		}
	}
	if err = archive.Close(); err != nil {
		return report, err
	}
	if err = zipper.Close(); err != nil {
		return report, err
	}
	if err = out.Sync(); err != nil {
		return report, err
	}
	info, err := out.Stat()
	if err != nil {
		return report, err
	}
	if err = out.Close(); err != nil {
		return report, err
	}
	if err = syncDirectory(parent); err != nil {
		return report, err
	}
	return Report{Path: abs, SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: info.Size()}, nil
}

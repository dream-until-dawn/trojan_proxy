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
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
	"github.com/dream-until-dawn/trojan_proxy/internal/maintenance"
)

var digestFormat = regexp.MustCompile(`^[0-9a-f]{64}$`)

func decodeStrict(path string, limit int64, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(io.LimitReader(f, limit+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("备份清单或部署描述无效")
	}
	return nil
}

func extract(path, expected, stage string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxArchive {
		return errors.New("备份必须为不超过72MiB的普通文件")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	zipper, err := gzip.NewReader(io.TeeReader(io.LimitReader(f, maxArchive+1), h))
	if err != nil {
		return errors.New("备份压缩格式无效")
	}
	defer zipper.Close()
	archive := tar.NewReader(zipper)
	seen := map[string]bool{}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("备份归档损坏")
		}
		limit, ok := fileLimits[header.Name]
		if !ok || seen[header.Name] || header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > limit {
			return errors.New("备份包含未知、重复、链接或超限条目")
		}
		seen[header.Name] = true
		out, err := os.OpenFile(filepath.Join(stage, header.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = io.CopyN(out, archive, header.Size)
		if err == nil {
			err = out.Sync()
		}
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if len(seen) != len(fileLimits) {
		return errors.New("备份缺少必需条目")
	}
	// 继续消费gzip尾部以核对CRC及完整压缩摘要，同时拒绝附加数据或拼接归档。
	extra, err := io.Copy(io.Discard, io.LimitReader(zipper, 1))
	if err != nil || extra != 0 {
		return errors.New("备份包含附加数据或压缩校验错误")
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("备份SHA256与可信记录不符")
	}
	var m manifest
	if err = decodeStrict(filepath.Join(stage, "manifest.json"), 65536, &m); err != nil {
		return err
	}
	if m.Version != 1 || len(m.Files) != 3 {
		return errors.New("备份格式版本或清单条目不受支持")
	}
	for _, name := range []string{"control.db", "master.key", "deployment.json"} {
		digest, err := hashFile(filepath.Join(stage, name))
		if err != nil {
			return err
		}
		if !digestFormat.MatchString(m.Files[name]) || digest != m.Files[name] {
			return errors.New("备份文件校验失败")
		}
	}
	return nil
}

func emptyRestoreTarget(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("还原目录必须是普通专用目录")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() != "maintenance.lock" && entry.Name() != ".trojan-proxy-volume" {
			return errors.New("还原目标非空，拒绝覆盖现有认证或业务状态")
		}
	}
	return nil
}

// Restore 只用于空卷冷还原；可信摘要必须由所有者从归档之外的记录提供。
// 恢复标志让控制服务拒绝旧凭据，所有者完成SSH重绑后才能恢复管理登录。
func Restore(ctx context.Context, c config.Config, archive, expected string) error {
	expected = strings.ToLower(expected)
	if !digestFormat.MatchString(expected) {
		return errors.New("还原必须提供可信记录中的完整SHA256")
	}
	lock, err := maintenance.Acquire(c.DataDir, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = emptyRestoreTarget(c.DataDir); err != nil {
		return err
	}
	abs, err := filepath.Abs(c.DataDir)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(abs, ".restore-")
	if err != nil {
		return err
	}
	defer cleanTemporary(stage, abs, ".restore-")
	if err = extract(archive, expected, stage); err != nil {
		return err
	}
	var descriptor config.Config
	if err = decodeStrict(filepath.Join(stage, "deployment.json"), 1<<20, &descriptor); err != nil {
		return err
	}
	if err = descriptor.Validate(); err != nil {
		return errors.New("备份部署描述不符合约束")
	}
	if descriptor.ControlPort != c.ControlPort || !maps.Equal(descriptor.PublicDirectories, c.PublicDirectories) {
		return errors.New("请使用备份中相同的内控端口及授权目录挂载后再还原")
	}
	// 旧修订仍从部署文件读取业务参数，不能用空域名默认文件悄悄覆盖它们。
	// 已迁入设置库的实例也保留部署防护基线，避免恢复时撤掉自身地址保护。
	if descriptor.Domain != c.Domain || descriptor.AdminPort != c.AdminPort || descriptor.VPNPort != c.VPNPort ||
		descriptor.StandardIngress != c.StandardIngress || descriptor.VPNManagement != c.VPNManagement ||
		descriptor.VPNResolver != c.VPNResolver || !slices.Equal(descriptor.VPNAddresses, c.VPNAddresses) {
		return errors.New("还原必须沿用备份的部署参数；数据目录可以迁移，业务设置请恢复后在后台调整")
	}
	key, err := readKey(stage)
	if err != nil {
		return err
	}
	defer clear(key)
	if err = validateDatabase(ctx, filepath.Join(stage, "control.db"), key, c); err != nil {
		return err
	}
	flag, err := os.OpenFile(filepath.Join(abs, "recovery-required"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = flag.WriteString("还原后必须通过SSH重绑管理员，并核实此主机的域名、IP和目录挂载\n")
	if err == nil {
		err = flag.Sync()
	}
	closeErr := flag.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = syncDirectory(abs); err != nil {
		return err
	}
	for _, name := range []string{"master.key", "control.db", "deployment.json"} {
		target := name
		if name == "deployment.json" {
			target = "restored-deployment.json"
		}
		if err = os.Rename(filepath.Join(stage, name), filepath.Join(abs, target)); err != nil {
			return err
		}
	}
	return syncDirectory(abs)
}

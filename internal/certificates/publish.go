package certificates

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Prepared 是不可变版本引用，激活由运行协调器另行提交。
type Prepared struct {
	Version         string   `json:"version"`
	Info            Metadata `json:"info"`
	CertificatePath string   `json:"-"`
	KeyPath         string   `json:"-"`
}

func durableFile(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
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

// Prepare 将已校验材料写入完整版本；不会覆盖已有文件，也不会改变运行引擎。
func Prepare(directory string, pair Pair) (Prepared, error) {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return Prepared{}, err
	}
	directory = abs
	if len(pair.certificate) == 0 || len(pair.key) == 0 || pair.info.Fingerprint == "" {
		return Prepared{}, errors.New("不能发布未经校验的证书材料")
	}
	if err := os.MkdirAll(directory, 0750); err != nil {
		return Prepared{}, err
	}
	stat, err := os.Lstat(directory)
	if err != nil {
		return Prepared{}, err
	}
	if !stat.IsDir() || stat.Mode()&os.ModeSymlink != 0 {
		return Prepared{}, errors.New("证书发布根目录不是普通目录")
	}
	if runtime.GOOS != "windows" && stat.Mode().Perm()&0027 != 0 {
		return Prepared{}, errors.New("证书发布目录权限过宽")
	}
	digest := sha256.Sum256(pair.certificate)
	version := hex.EncodeToString(digest[:])
	final := filepath.Join(directory, version)
	result := Prepared{Version: version, Info: pair.info, CertificatePath: filepath.Join(final, "fullchain.pem"), KeyPath: filepath.Join(final, "private.key")}
	if existing, err := os.Lstat(final); err == nil {
		if !existing.IsDir() || existing.Mode()&os.ModeSymlink != 0 {
			return Prepared{}, errors.New("证书版本路径不安全")
		}
		cert, err := os.ReadFile(result.CertificatePath)
		if err != nil {
			return Prepared{}, err
		}
		key, err := os.ReadFile(result.KeyPath)
		if err != nil {
			return Prepared{}, err
		}
		// 同一叶证书可用不同PEM编码表达私钥，但这里保持输入完全一致才复用。
		if !bytes.Equal(cert, pair.certificate) || !bytes.Equal(key, pair.key) {
			return Prepared{}, errors.New("既有证书版本内容不一致，拒绝覆盖")
		}
		if err = syncDirectory(directory); err != nil {
			return Prepared{}, err
		}
		return result, nil
	} else if !os.IsNotExist(err) {
		return Prepared{}, err
	}
	temp, err := os.MkdirTemp(directory, ".prepare-")
	if err != nil {
		return Prepared{}, err
	}
	defer func() {
		// 删除前核实绝对路径是发布根目录的直接临时子目录，绝不清理版本目录。
		if filepath.Dir(temp) == directory && strings.HasPrefix(filepath.Base(temp), ".prepare-") {
			os.RemoveAll(temp)
		}
	}()
	if err = os.Chmod(temp, 0750); err != nil {
		return Prepared{}, err
	}
	if err = durableFile(filepath.Join(temp, "fullchain.pem"), pair.certificate); err != nil {
		return Prepared{}, err
	}
	if err = durableFile(filepath.Join(temp, "private.key"), pair.key); err != nil {
		return Prepared{}, err
	}
	if err = syncDirectory(temp); err != nil {
		return Prepared{}, err
	}
	if err = os.Rename(temp, final); err != nil {
		return Prepared{}, err
	}
	if err = syncDirectory(directory); err != nil {
		return Prepared{}, err
	}
	return result, nil
}

package certificates

import (
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dream-until-dawn/trojan_proxy/internal/files"
)

var domainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func boundedRead(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("证书缓存文件超出限制")
	}
	return b, nil
}

// ReadPairFiles 只用于明确授权的本地CLI路径，HTTP接口不得接受任意主机路径。
func ReadPairFiles(certPath, keyPath, domain string, now time.Time, roots *x509.CertPool) (Pair, error) {
	cert, err := boundedRead(certPath, 1024*1024)
	if err != nil {
		return Pair{}, err
	}
	key, err := boundedRead(keyPath, 65536)
	if err != nil {
		return Pair{}, err
	}
	return ValidatePair(cert, key, domain, now, roots)
}

// ReadManaged 适配固定Caddy版本的 issuer/domain/domain.crt 与 .key 缓存结构。
// 仅选择已授权域名且仍可信的候选，不读取ACME账号文件。
func ReadManaged(directory, domain string, now time.Time, roots *x509.CertPool) (Pair, error) {
	if domain == "" || len(domain) > 253 {
		return Pair{}, errors.New("缓存域名无效")
	}
	for _, label := range strings.Split(domain, ".") {
		if !domainLabel.MatchString(label) {
			return Pair{}, errors.New("缓存域名无效")
		}
	}
	root, err := files.OpenRoot(directory)
	if err != nil {
		return Pair{}, err
	}
	defer root.Close()
	issuers, err := root.List(".")
	if err != nil {
		return Pair{}, err
	}
	if len(issuers) > 32 {
		return Pair{}, errors.New("缓存签发者数量异常")
	}
	var selected Pair
	for _, issuer := range issuers {
		if !issuer.Directory {
			continue
		}
		prefix := filepath.ToSlash(filepath.Join(issuer.Name, domain, domain))
		read := func(name string, limit int64) ([]byte, error) {
			f, err := root.Open(name)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			b, err := io.ReadAll(io.LimitReader(f, limit+1))
			if err != nil || int64(len(b)) > limit {
				return nil, errors.New("缓存证书材料无法读取")
			}
			return b, nil
		}
		cert, err := read(prefix+".crt", 1024*1024)
		if err != nil {
			continue
		}
		key, err := read(prefix+".key", 65536)
		if err != nil {
			continue
		}
		pair, err := ValidatePair(cert, key, domain, now, roots)
		if err != nil {
			continue
		}
		if selected.info.Fingerprint == "" || pair.info.NotAfter.After(selected.info.NotAfter) {
			selected = pair
		}
	}
	if selected.info.Fingerprint == "" {
		return Pair{}, errors.New("未找到域名匹配、有效且密钥配对的托管证书")
	}
	return selected, nil
}

// Package settings 管理可变业务设置；不接收宿主机路径和原始引擎配置。
package settings

import (
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/dream-until-dawn/trojan_proxy/internal/config"
)

// Directory 通过受信任挂载根ID和根内相对路径定义发布范围。
type Directory struct {
	ID       string `json:"id"`
	Root     string `json:"root"`
	Relative string `json:"relative"`
}

// Site 不含管理员、VPN口令、私钥、宿主路径及内控socket。
type Site struct {
	Domain            string      `json:"domain"`
	AdminPort         int         `json:"admin_port"`
	VPNPort           int         `json:"vpn_port"`
	VPNAddresses      []string    `json:"vpn_own_addresses"`
	VPNResolver       string      `json:"vpn_resolver"`
	CertificateSource string      `json:"certificate_source"`
	ACMEEmail         string      `json:"acme_email"`
	ImportedVersion   string      `json:"imported_version,omitempty"`
	Directories       []Directory `json:"directories"`
}

// Document 作为完整修订的一部分保存；版本升级必须明确迁移，不做宽松解码。
type Document struct {
	Version int         `json:"version"`
	Site    Site        `json:"site"`
	Pending *Transition `json:"pending,omitempty"`
}

// Transition 只保存在受限数据库，恢复快照绝不作为后台普通状态返回。
type Transition struct {
	Candidate           Site   `json:"candidate"`
	Deadline            int64  `json:"deadline"`
	PreviousGateway     string `json:"previous_gateway"`
	PreviousVPN         string `json:"previous_vpn"`
	PreviousFingerprint string `json:"previous_fingerprint"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var publishedVersion = regexp.MustCompile(`^[0-9a-f]{64}$`)

// FromLegacy 仅供首次导入；不可将此函数用于覆盖已有网页设置。
func FromLegacy(c config.Config) Document {
	site := Site{Domain: c.Domain, AdminPort: c.AdminPort, VPNPort: c.VPNPort, VPNAddresses: append([]string{}, c.VPNAddresses...), VPNResolver: c.VPNResolver, CertificateSource: "none", Directories: make([]Directory, 0, len(c.PublicDirectories))}
	if site.VPNResolver == "" {
		site.VPNResolver = "9.9.9.9:53"
	}
	if c.Domain != "" {
		site.CertificateSource = "imported"
	}
	ids := make([]string, 0, len(c.PublicDirectories))
	for id := range c.PublicDirectories {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		site.Directories = append(site.Directories, Directory{ID: id, Root: id, Relative: "."})
	}
	return Document{Version: 1, Site: site}
}

// Validate 将部署边界重新合并后校验；候选设置不能更改内控端口或增加任意挂载。
func (d Document) Validate(deployment config.Config) error {
	if d.Version != 1 {
		return errors.New("业务设置版本不受支持")
	}
	c := deployment
	c.Domain = d.Site.Domain
	c.AdminPort = d.Site.AdminPort
	c.VPNPort = d.Site.VPNPort
	c.VPNAddresses = d.Site.VPNAddresses
	c.VPNResolver = d.Site.VPNResolver
	// 草稿可以尚未确认公网地址；真正启用VPN仍必须通过协议层的完整校验。
	c.VPNManagement = false
	if err := c.Validate(); err != nil {
		return err
	}
	if len(d.Site.VPNAddresses) > 64 {
		return errors.New("服务器自身地址最多64个")
	}
	switch d.Site.CertificateSource {
	case "none":
		if d.Site.Domain != "" {
			return errors.New("域名模式必须选择证书来源")
		}
	case "imported", "automatic":
		if d.Site.Domain == "" {
			return errors.New("证书模式必须先设置域名")
		}
	default:
		return errors.New("未知证书来源")
	}
	if d.Site.ImportedVersion != "" && (d.Site.CertificateSource != "imported" || !publishedVersion.MatchString(d.Site.ImportedVersion)) {
		return errors.New("导入证书版本必须来自受控证书发布目录")
	}
	if d.Site.ACMEEmail != "" {
		address, err := mail.ParseAddress(d.Site.ACMEEmail)
		if err != nil || address.Address != d.Site.ACMEEmail || len(d.Site.ACMEEmail) > 254 {
			return errors.New("ACME邮箱格式不正确")
		}
	}
	if len(d.Site.Directories) > 100 {
		return errors.New("发布目录最多100个")
	}
	seen := map[string]bool{}
	for _, directory := range d.Site.Directories {
		if !identifier.MatchString(directory.ID) || seen[directory.ID] || deployment.PublicDirectories[directory.Root] == "" {
			return errors.New("目录ID重复、无效或挂载根未授权")
		}
		seen[directory.ID] = true
		relative := directory.Relative
		if relative == "" || len(relative) > 512 || strings.HasPrefix(relative, "/") || path.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, "../") || strings.ContainsAny(relative, ":\\\x00\r\n") {
			return errors.New("发布路径必须为挂载根内的规范相对路径")
		}
	}
	if d.Pending != nil {
		if d.Pending.Deadline <= 0 {
			return errors.New("入口切换期限无效")
		}
		if err := (Document{Version: 1, Site: d.Pending.Candidate}).Validate(deployment); err != nil {
			return err
		}
	}
	return nil
}

// Decode 拒绝未知字段、超大输入及尾随JSON；损坏时不能回退到静态配置。
func Decode(body string, deployment config.Config) (Document, error) {
	var document Document
	if len(body) > 2*1024*1024 {
		return document, errors.New("业务设置过大")
	}
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Document{}, errors.New("业务设置包含尾随数据")
	}
	return document, document.Validate(deployment)
}

// Encode 先验证边界，返回可持久化的规范JSON。
func (d Document) Encode(deployment config.Config) (string, error) {
	if err := d.Validate(deployment); err != nil {
		return "", err
	}
	body, err := json.Marshal(d)
	return string(body), err
}

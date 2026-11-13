package certificates

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Selection 只选择受限证书来源，不接受文件名或签发器URL。
type Selection struct {
	Domain          string
	Source          string
	ImportedVersion string
}

// Manager 的根目录来自部署。测试可注入信任根，生产必须使用系统根。
type Manager struct {
	mu                 sync.Mutex
	PublishedDirectory string
	ManagedDirectory   string
	LegacyDirectory    string
	LegacyDomain       string
	Roots              *x509.CertPool
	Now                func() time.Time
	Current            func(context.Context) (Selection, error)
	Additional         func(context.Context) ([]Selection, error)
}

// State 只返回当前选择的公开证书元数据，不包含材料、缓存路径或账户信息。
type State struct {
	Available bool      `json:"available"`
	Domain    string    `json:"domain"`
	Source    string    `json:"source"`
	Ready     bool      `json:"ready"`
	Info      *Metadata `json:"info,omitempty"`
	Message   string    `json:"message"`
	Domains   []State   `json:"domains,omitempty"`
}

func (m *Manager) Status(ctx context.Context) (State, error) {
	if m.Current == nil {
		return State{}, errors.New("证书设置来源尚未连接")
	}
	selection, err := m.Current(ctx)
	if err != nil {
		return State{}, err
	}
	state := State{Available: true, Domain: selection.Domain, Source: selection.Source, Message: "证书尚未就绪，请核对域名、DNS和证书来源"}
	if selection.Domain == "" {
		state.Message = "无域名模式使用HTTP，后台通过SSH隧道管理"
		return state, nil
	}
	pair, err := m.Pair(selection)
	if err == nil {
		info := pair.Metadata()
		state.Info = &info
		state.Ready = true
		state.Message = "证书可信且在有效期内"
	}
	if m.Additional != nil {
		selections, e := m.Additional(ctx)
		if e != nil {
			return State{}, e
		}
		for _, selected := range selections {
			item := State{Available: true, Domain: selected.Domain, Source: selected.Source, Message: "证书尚未就绪，请核对DNS和80端口"}
			if pair, e := m.Pair(selected); e == nil {
				metadata := pair.Metadata()
				item.Ready = true
				item.Info = &metadata
				item.Message = "证书可信且在有效期内"
			}
			state.Domains = append(state.Domains, item)
		}
	}
	return state, nil
}

var managedVersion = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Pair 重新验证有效期与可信链；历史发布版本也不能绕过过期检查。
func (m *Manager) Pair(selection Selection) (Pair, error) {
	switch selection.Source {
	case "automatic":
		return ReadManaged(m.ManagedDirectory, selection.Domain, m.now(), m.Roots)
	case "imported":
		if selection.ImportedVersion != "" {
			if !managedVersion.MatchString(selection.ImportedVersion) {
				return Pair{}, errors.New("证书版本无效")
			}
			root := filepath.Join(m.PublishedDirectory, selection.ImportedVersion)
			return ReadPairFiles(filepath.Join(root, "fullchain.pem"), filepath.Join(root, "private.key"), selection.Domain, m.now(), m.Roots)
		}
		// 旧部署只授权其原域名与固定导入路径，不能借此读取任意证书。
		if selection.Domain == "" || selection.Domain != m.LegacyDomain || m.LegacyDirectory == "" {
			return Pair{}, errors.New("请先导入该域名的有效证书")
		}
		return ReadPairFiles(filepath.Join(m.LegacyDirectory, "fullchain.cer"), filepath.Join(m.LegacyDirectory, "private.key"), selection.Domain, m.now(), m.Roots)
	default:
		return Pair{}, errors.New("该入口没有证书来源")
	}
}

// Import 校验后发布不可变版本，不自动替换正在使用的证书。
// 最多保留64个发布目录，避免反复上传把证书卷无限写满。
func (m *Manager) Import(domain string, chain, key []byte) (Prepared, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pair, err := ValidatePair(chain, key, domain, m.now(), m.Roots)
	if err != nil {
		return Prepared{}, err
	}
	if err = os.MkdirAll(m.PublishedDirectory, 0750); err != nil {
		return Prepared{}, err
	}
	root, err := os.Open(m.PublishedDirectory)
	if err != nil {
		return Prepared{}, err
	}
	entries, err := root.ReadDir(65)
	root.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return Prepared{}, err
	}
	digest := sha256.Sum256(pair.certificate)
	version := hex.EncodeToString(digest[:])
	if len(entries) >= 64 {
		// 重复导入已经存在的版本不占用新空间；Prepare仍核对内容一致性。
		if info, err := os.Stat(filepath.Join(m.PublishedDirectory, version)); err != nil || !info.IsDir() {
			return Prepared{}, errors.New("证书发布空间达到上限，请先通过SSH清理不再引用的旧版本")
		}
	}
	return Prepare(m.PublishedDirectory, pair)
}

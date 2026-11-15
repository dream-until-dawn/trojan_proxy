// Package trojanprefix 只识别原生Trojan帧形状；身份认证仍由独立引擎完成。
package trojanprefix

import (
	"errors"
	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"
	"github.com/mholt/caddy-l4/modules/l4tls"
	"strings"
)

func init() { caddy.RegisterModule(&Matcher{}) }

// Matcher 将分流严格限制在指定TLS SNI，不读取或持有VPN口令。
type Matcher struct {
	SNI string "json:\"sni\""
}

func (*Matcher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "layer4.matchers.trojan_prefix", New: func() caddy.Module { return new(Matcher) }}
}
func (m *Matcher) Validate() error {
	if len(m.SNI) > 253 || !strings.Contains(m.SNI, ".") || strings.ContainsAny(m.SNI, "{}*:/\\ \t\r\n") || strings.ToLower(m.SNI) != m.SNI {
		return errors.New("Trojan分流必须指定精确小写域名")
	}
	return nil
}

// Match 只检查已预取字节，不消费连接，不等待固定58字节后才识别普通HTTP。
// 不完整前缀受layer4匹配期限和缓冲上限保护。
func (m *Matcher) Match(cx *layer4.Connection) (bool, error) {
	states := l4tls.GetConnectionStates(cx)
	if len(states) == 0 || states[len(states)-1].ServerName != m.SNI {
		return false, nil
	}
	return matchPrefix(cx.MatchingBytes())
}
func matchPrefix(data []byte) (bool, error) {
	for _, b := range data[:min(len(data), 56)] {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false, nil
		}
	}
	if len(data) < 58 {
		return false, layer4.ErrConsumedAllPrefetchedBytes
	}
	return data[56] == '\r' && data[57] == '\n', nil
}

var _ layer4.ConnMatcher = (*Matcher)(nil)
var _ caddy.Validator = (*Matcher)(nil)

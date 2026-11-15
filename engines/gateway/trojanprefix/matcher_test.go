package trojanprefix

import (
	"crypto/tls"
	"errors"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
	"net"
	"strings"
	"testing"
)

func TestExactSNIOnly(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	cx := layer4.WrapConnection(a, []byte(strings.Repeat("a", 56)+"\r\n"), zap.NewNop())
	m := &Matcher{SNI: "vpn.test"}
	for _, name := range []string{"vpn.test", "business.vpn.test", ""} {
		cx.SetVar(layer4.TLSConnectionStatesVarName, []*tls.ConnectionState{{ServerName: name}})
		matched, e := m.Match(cx)
		if e != nil || matched != (name == "vpn.test") {
			t.Fatal("business SNI classified as Trojan", name, matched, e)
		}
	}
}

func TestIncrementalPrefixAndShortHTTP(t *testing.T) {
	for _, raw := range []string{"G", "GET / HTTP/1.0\r\n\r\n", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", strings.Repeat("a", 55) + "g\r\n", strings.Repeat("a", 56) + "xx"} {
		matched, err := matchPrefix([]byte(raw))
		if matched || err != nil {
			t.Fatalf("non-Trojan or short HTTP delayed: %q %v", raw, err)
		}
	}
	for _, raw := range []string{"", "a", strings.Repeat("0", 56), strings.Repeat("a", 56) + "\r"} {
		matched, err := matchPrefix([]byte(raw))
		if matched || !errors.Is(err, layer4.ErrConsumedAllPrefetchedBytes) {
			t.Fatal("incomplete prefix accepted", err)
		}
	}
	for _, raw := range []string{strings.Repeat("a", 56) + "\r\n", strings.Repeat("1", 56) + "\r\npayload"} {
		matched, err := matchPrefix([]byte(raw))
		if !matched || err != nil {
			t.Fatal("complete prefix rejected", err)
		}
	}
	if (&Matcher{SNI: "*.fixture.test"}).Validate() == nil {
		t.Fatal("wildcard SNI accepted")
	}
}

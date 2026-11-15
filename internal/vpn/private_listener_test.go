package vpn

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrivateListenerVersionAndPublicExport(t *testing.T) {
	base, d := profileFixture(t)
	d.Profile.Version = 2
	d.Profile.LoopbackOnly = true
	body, e := CompileTrojan(base, d)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(body, "\"listen\":\"127.0.0.1\"") {
		t.Fatal("private listener compiled as public")
	}
	exported, e := ExportClash(base, d)
	if e != nil {
		t.Fatal(e)
	}
	var config struct{ Proxies []struct{ Port int } }
	if e = json.Unmarshal(exported, &config); e != nil || config.Proxies[0].Port != 443 {
		t.Fatal("private backend port leaked into export", e)
	}
	if _, e = ExportClashPort(base, d, 19443); e == nil {
		t.Fatal("private backend exported as public")
	}
	encoded, e := EncodeCommand(d)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeCommand(encoded)
	if e != nil || decoded.Profile == nil || !decoded.Profile.LoopbackOnly {
		t.Fatal("private command lost intent", e)
	}
	for _, p := range []Profile{{Version: 1, LoopbackOnly: true}, {Version: 2, LoopbackOnly: false}, {Version: 3, LoopbackOnly: true}} {
		copy := *d.Profile
		copy.Version, copy.LoopbackOnly = p.Version, p.LoopbackOnly
		bad := d
		bad.Profile = &copy
		if _, e = CompileTrojan(base, bad); e == nil {
			t.Fatal("private mode accepted ambiguous profile version", p.Version, p.LoopbackOnly)
		}
	}
	d.Profile.Version = 1
	d.Profile.LoopbackOnly = false
	body, e = CompileTrojan(base, d)
	if e != nil || !strings.Contains(body, "\"listen\":\"::\"") {
		t.Fatal("legacy public listener changed", e)
	}
}

package vpn

import (
	"encoding/json"
	"testing"
)

func TestPublic443ExportDoesNotChangeEngine(t *testing.T) {
	base, desired := profileFixture(t)
	engine, e := CompileTrojan(base, desired)
	if e != nil {
		t.Fatal(e)
	}
	body, e := ExportClashPort(base, desired, 443)
	if e != nil {
		t.Fatal(e)
	}
	var profile struct{ Proxies []struct{ Port int } }
	if e = json.Unmarshal(body, &profile); e != nil || profile.Proxies[0].Port != 443 {
		t.Fatal("public shared port ignored", e)
	}
	after, e := CompileTrojan(base, desired)
	if e != nil || after != engine {
		t.Fatal("export moved actual engine listener", e)
	}
	if _, e = ExportClashPort(base, desired, 12345); e == nil {
		t.Fatal("arbitrary public port accepted")
	}
	body, e = ExportClash(base, desired)
	if e != nil {
		t.Fatal(e)
	}
	json.Unmarshal(body, &profile)
	if profile.Proxies[0].Port != desired.Profile.Port {
		t.Fatal("disabled shared export changed legacy port")
	}
}

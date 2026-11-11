package vpn

import (
	"encoding/json"
	"strings"
	"testing"
)

func profileFixture(t *testing.T) (Settings, Desired) {
	t.Helper()
	base, desired := fixture()
	base.ReservedPorts = []int{18090, 18091, 18092}
	desired.Profile = &Profile{Version: 1, Domain: "next.example", Port: 19443, AdminPort: 8006, OwnAddresses: []string{"203.0.113.2"}, Resolver: "1.1.1.1:53"}
	return base, desired
}

func TestRuntimeProfileCompileExportAndDeploymentGuards(t *testing.T) {
	base, desired := profileFixture(t)
	body, err := CompileTrojan(base, desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"listen_port":19443`, `"server":"1.1.1.1"`, `"203.0.113.2/32"`, `"47.82.112.245/32"`} {
		if !strings.Contains(body, expected) {
			t.Fatal("runtime profile ignored or removed protected address", expected, body)
		}
	}
	exported, err := ExportClash(base, desired)
	if err != nil || !strings.Contains(string(exported), `"server": "next.example"`) || !strings.Contains(string(exported), `"port": 19443`) {
		t.Fatal("export diverged from runtime profile", string(exported), err)
	}
	for _, port := range []int{80, 443, 18090, 18091, 18092, 8006} {
		copy := *desired.Profile
		copy.Port = port
		bad := desired
		bad.Profile = &copy
		if _, err := CompileTrojan(base, bad); err == nil {
			t.Fatal("runtime profile accepted protected port", port)
		}
	}
	for _, mutate := range []func(*Profile){
		func(p *Profile) { p.Version = 2 }, func(p *Profile) { p.Domain = "https://next.example" },
		func(p *Profile) { p.Resolver = "dns.example:53" }, func(p *Profile) { p.OwnAddresses = nil },
		func(p *Profile) { p.OwnAddresses = []string{"not-an-ip"} },
	} {
		copy := *desired.Profile
		mutate(&copy)
		bad := desired
		bad.Profile = &copy
		if _, err := CompileTrojan(base, bad); err == nil {
			t.Fatal("runtime profile accepted malformed parameters", copy)
		}
	}
}

func TestRuntimeProfileWireCompatibilityAndStrictDecoding(t *testing.T) {
	_, desired := profileFixture(t)
	legacy := desired
	legacy.Profile = nil
	body, err := EncodeCommand(legacy)
	expected := `{"enabled":true,"password":"` + legacy.Password + `","certificate_version":"` + legacy.CertificateVersion + `"}`
	if err != nil || string(body) != expected {
		t.Fatal("legacy command encoding changed", string(body), err)
	}
	body, err = EncodeCommand(desired)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCommand(body)
	if err != nil || CommandFingerprint(decoded) != CommandFingerprint(desired) {
		t.Fatal("profile command did not round trip", err)
	}
	sealed, err := Seal(make([]byte, 32), desired)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(make([]byte, 32), sealed)
	if err != nil || CommandFingerprint(opened) != CommandFingerprint(desired) {
		t.Fatal("profile encrypted command did not round trip", err)
	}
	public, err := json.Marshal(desired)
	if err != nil || strings.Contains(string(public), "own_addresses") || strings.Contains(string(public), desired.Password) {
		t.Fatal("normal JSON exposed private command", string(public), err)
	}
	bad := strings.Replace(string(body), `"version":1`, `"version":1,"engine_config":{}`, 1)
	if _, err := DecodeCommand([]byte(bad)); err == nil {
		t.Fatal("unknown runtime profile option accepted")
	}
	desired.Enabled = false
	desired.Password = ""
	desired.CertificateVersion = ""
	body, _ = EncodeCommand(desired)
	if _, err := DecodeCommand(body); err == nil {
		t.Fatal("stop command accepted runtime profile")
	}
}

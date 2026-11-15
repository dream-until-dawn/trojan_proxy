package gateway

import (
	"strings"
	"testing"
)

func TestSharedTrojanTLSAndTransitionBoundaries(t *testing.T) {
	s := pathFixture()
	off, e := Compile(s, nil)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(off, "listener_wrappers") {
		t.Fatal("disabled shared mode changed listener")
	}
	s.SharedTrojan = &SharedTrojan{Port: 18443}
	on, e := Compile(s, nil)
	if e != nil {
		t.Fatal(e)
	}
	server := pathServers(t, on)["public_443"].(map[string]any)
	if server["tls_connection_policies"] != nil || server["listener_wrappers"] == nil {
		t.Fatal("shared TLS terminated twice or listener missing")
	}
	for _, part := range []string{"trojan_prefix", "127.0.0.1:18443", "server_name", "qin-xin.top"} {
		if !strings.Contains(on, part) {
			t.Fatal("missing fixed TLS/shared boundary", part)
		}
	}
	if strings.Contains(on, "insecure_skip_verify") {
		t.Fatal("backend TLS verification bypassed")
	}
	next := s
	next.SharedTrojan = nil
	dual, e := CompileAdminTransition(s, next, nil)
	if e != nil {
		t.Fatal(e)
	}
	dualServer := pathServers(t, dual)["public_443"].(map[string]any)
	if dualServer["tls_connection_policies"] != nil || dualServer["listener_wrappers"] == nil {
		t.Fatal("shared transition double TLS or lost current entry")
	}
	current := s
	current.SharedTrojan = nil
	dual, e = CompileAdminTransition(current, s, nil)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(dual, "listener_wrappers") {
		t.Fatal("candidate shared mode activated before confirmation")
	}
	s.SharedTrojan.Port = 18090
	if _, e = Compile(s, nil); e == nil {
		t.Fatal("shared arbitrary upstream accepted")
	}
	s.SharedTrojan.Port = 18443
	s.Ingress = nil
	if _, e = Compile(s, nil); e == nil {
		t.Fatal("shared without standard ingress accepted")
	}
}

package vpn

import (
	"encoding/json"
	"testing"
)

func TestSubscriptionDirectPrecedesCatchAllAndPreservesNode(t *testing.T) {
	input := []byte(`{"proxies":[{"password":"fixture-sentinel","port":18443}],"rules":["DOMAIN,proxy.fixture.test,DIRECT","MATCH,node"]}`)
	body, err := WithSubscriptionDirect(input, "proxy.fixture.test")
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		Proxies []struct {
			Password string
			Port     int
		}
		Rules []string
	}
	if err = json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	if len(value.Rules) != 2 || value.Rules[0] != "DOMAIN,proxy.fixture.test,DIRECT" || value.Rules[1] != "MATCH,node" || value.Proxies[0].Password != "fixture-sentinel" || value.Proxies[0].Port != 18443 {
		t.Fatal("subscription direct route corrupted config", string(body))
	}
	for _, host := range []string{"untrusted,PROXY", "bad\n.fixture.test", "-bad.fixture.test", ""} {
		if _, err = WithSubscriptionDirect(input, host); err == nil {
			t.Fatal("unsafe subscription host accepted")
		}
	}
	for _, body := range []string{"null", `{"rules":"bad"}`, `{}`} {
		if _, err = WithSubscriptionDirect([]byte(body), "proxy.fixture.test"); err == nil {
			t.Fatal("invalid profile accepted")
		}
	}
}

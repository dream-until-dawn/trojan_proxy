package adminentry

import "testing"

func TestPathValidationAndIdentity(t *testing.T) {
	for _, p := range []string{"", "/proxy", "/admin/tools"} {
		if err := ValidatePath(p); err != nil {
			t.Fatal(p, err)
		}
	}
	for _, p := range []string{"/", "proxy", "/proxy/", "/../proxy", "/api", "/api/v1", "/healthz", "/proxy%2fsecret", "//proxy", "/Proxy"} {
		if ValidatePath(p) == nil {
			t.Fatal("unsafe management path accepted", p)
		}
	}
	if got := ForSite("qin-xin.top", 8007, 18090, "/proxy"); got.Origin != "https://qin-xin.top" || got.Identity() != "https://qin-xin.top/proxy" {
		t.Fatal(got)
	}
	if got := ForSite("qin-xin.top", 8007, 18090, "").Identity(); got != "https://qin-xin.top:8007" {
		t.Fatal(got)
	}
}

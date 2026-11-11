package welcome

import (
	"strings"
	"testing"
)

func TestWelcomeEscapingStatusAndNoInternalDetails(t *testing.T) {
	for _, ready := range []bool{true, false} {
		body, err := Render(`<script>alert(1)</script>`, ready)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") {
			t.Fatal("welcome display name was not escaped")
		}
		for _, secret := range []string{"VPN", "Trojan", "代理", "后台", "/api/", "fetch(", "http://", "https://"} {
			if strings.Contains(body, secret) {
				t.Fatal("internal detail or external dependency exposed", secret)
			}
		}
		if ready && !strings.Contains(body, "状态正常") {
			t.Fatal("missing green status")
		}
		if !ready && !strings.Contains(body, "暂时不可用") {
			t.Fatal("missing red status")
		}
	}
	body, err := Render("", true)
	if err != nil || !strings.Contains(body, "<h1>欢迎访问</h1>") {
		t.Fatal("no-domain welcome incorrect", err)
	}
}

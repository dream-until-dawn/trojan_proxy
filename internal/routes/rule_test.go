package routes

import "testing"

func baseline() Rule {
	return Rule{ID: "app", Name: "本机应用", Port: 18001, Path: "/app", Kind: "proxy", UpstreamIP: "127.0.0.1", UpstreamPort: 3000}
}
func policy() Policy {
	return Policy{AdminPort: 8007, ControlPort: 18090, VPNPort: 18443, Directories: map[string]string{"public": "/srv/public"}}
}
func TestRuleBoundary(t *testing.T) {
	if err := ValidateSet([]Rule{baseline()}, policy()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Rule){
		"admin-listener": func(r *Rule) { r.Port = 8007 }, "unclaimed-80": func(r *Rule) { r.Port = 80 },
		"metadata": func(r *Rule) { r.UpstreamIP = "169.254.169.254" }, "remote-ip": func(r *Rule) { r.UpstreamIP = "8.8.8.8" },
		"hostname-upstream": func(r *Rule) { r.UpstreamIP = "localhost" }, "management-upstream": func(r *Rule) { r.UpstreamPort = 18090 },
		"self-loop": func(r *Rule) { r.UpstreamPort = r.Port }, "ssh": func(r *Rule) { r.UpstreamPort = 22 },
		"traversal": func(r *Rule) { r.Path = "/a/../b" }, "encoded": func(r *Rule) { r.Path = "/%2e%2e" },
		"host-injection": func(r *Rule) { r.Host = "example.com:8007" }, "unmounted-directory": func(r *Rule) { r.Kind = "files"; r.DirectoryID = "private"; r.UpstreamIP = ""; r.UpstreamPort = 0 },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := baseline()
			change(&r)
			if err := ValidateSet([]Rule{r}, policy()); err == nil {
				t.Fatal("非法规则被接受")
			}
		})
	}
	a, b := baseline(), baseline()
	b.ID = "other"
	if ValidateSet([]Rule{a, b}, policy()) == nil {
		t.Fatal("重复匹配未拒绝")
	}
	b.Port = 18002
	b.UpstreamPort = a.Port
	if ValidateSet([]Rule{a, b}, policy()) == nil {
		t.Fatal("规则间循环未拒绝")
	}
}

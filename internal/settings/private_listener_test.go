package settings

import "testing"

func TestPrivateListenerRequiresShared443(t *testing.T) {
	deployment := deployment()
	deployment.StandardIngress = true
	d := FromLegacy(deployment)
	d.Site.VPNLoopbackOnly = true
	if e := d.Validate(deployment); e == nil {
		t.Fatal("private listener accepted without shared ingress")
	}
	d.Site.SharedTrojan443 = true
	if e := d.Validate(deployment); e != nil {
		t.Fatal("valid private shared settings rejected", e)
	}
}

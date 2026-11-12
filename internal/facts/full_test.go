package facts

import "testing"

func TestParseProbe(t *testing.T) {
	f := Facts{Firewall: "none"}
	f.parse("ssh_connection=198.51.100.7 50000 203.0.113.10 2222\ninit=systemd\npkg=apt-get\nfw=ufw\nfw_active=yes\nssh_unit=ssh\nvirt=kvm\n")
	if f.SSHPort != 2222 || f.ClientIP != "198.51.100.7" || f.PkgMgr != "apt" || f.Firewall != "ufw" || !f.FirewallActive || f.Virt != "kvm" {
		t.Errorf("parse = %+v", f)
	}
	if s := f.Summary(); s != "systemd · apt · ufw (active)" {
		t.Errorf("Summary = %q", s)
	}
}

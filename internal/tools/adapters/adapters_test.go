package adapters

import (
	"slices"
	"testing"
)

func TestParseUpgradable(t *testing.T) {
	tests := []struct {
		pm   Pkg
		out  string
		want []Upgrade
	}{
		{apt{}, "Listing...\nopenssl/noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]\ncurl/noble-updates 8.5.0-2ubuntu10.5 amd64 [upgradable from: 8.5.0-2ubuntu10.4]\n",
			[]Upgrade{{"openssl", "3.0.13-0ubuntu3.4"}, {"curl", "8.5.0-2ubuntu10.5"}}},
		{dnf{bin: "dnf"}, "\nopenssl.x86_64   1:3.0.7-27.el9   baseos\nkernel.x86_64 5.14.0-427 baseos\n",
			[]Upgrade{{"openssl", "1:3.0.7-27.el9"}, {"kernel", "5.14.0-427"}}},
		{apk{}, "Installed:  Available:\nopenssl-3.1.4-r0  < 3.1.4-r5\nmusl-1.2.4-r1 < 1.2.4-r2\n",
			[]Upgrade{{"openssl", "3.1.4-r5"}, {"musl", "1.2.4-r2"}}},
	}
	for _, tt := range tests {
		if got := tt.pm.ParseUpgradable(tt.out); !slices.Equal(got, tt.want) {
			t.Errorf("%s: got %v want %v", tt.pm.Name(), got, tt.want)
		}
	}
	if !AptSecurity("openssl/noble-security 3 amd64") || AptSecurity("curl/noble-updates 8 amd64") {
		t.Error("AptSecurity")
	}
}

func TestUfwAllows(t *testing.T) {
	out := "Added user rules (see 'ufw status' for running firewall):\nufw allow 80/tcp\nufw allow proto tcp from 10.0.0.0/8 to any port 2222\nufw allow OpenSSH\n"
	if !(ufw{}).Allows(out, 22) {
		t.Error("OpenSSH should allow 22")
	}
	if (ufw{}).Allows(out, 2222) {
		t.Error("a source-restricted rule doesn't keep the operator's access")
	}
	if !(ufw{}).Allows("ufw allow proto tcp from any to any port 2222\n", 2222) {
		t.Error("vio's own long form should count")
	}
}

func TestInverse(t *testing.T) {
	if Inverse("stop", true, true) != "start" || Inverse("start", false, true) != "stop" || Inverse("disable", true, true) != "enable" {
		t.Error("Inverse")
	}
}

func TestFirewalldRule(t *testing.T) {
	do, undo, err := firewalld{}.Rule("allow", Rule{Port: 443})
	if err != nil || do[0][2] != "--add-port=443/tcp" || undo[0][2] != "--remove-port=443/tcp" {
		t.Errorf("do %v undo %v err %v", do, undo, err)
	}
}

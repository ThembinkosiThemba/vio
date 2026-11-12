package policy

import (
	"testing"

	"github.com/ThembinkosiThemba/vio/internal/plan"
)

func act(tool string, tier plan.Tier, meta map[string]string, mod ...func(*plan.Action)) plan.Action {
	a := plan.Action{ID: "a1", Host: "web-1", Tool: tool, Tier: tier, Meta: meta}
	for _, m := range mod {
		m(&a)
	}
	return a
}

func TestBuiltinRules(t *testing.T) {
	base := Context{MaxTier: plan.Dangerous, HostTags: map[string][]string{"web-1": {"prod"}}}
	tests := []struct {
		name string
		ctx  func(Context) Context
		a    plan.Action
		want Decision
	}{
		{"plain change", nil, act("svc_control", plan.Change, nil), Allow},
		{"over ceiling", func(c Context) Context { c.MaxTier = plan.Change; return c }, act("shell_exec", plan.Dangerous, nil), Deny},
		{"dangerous confirms", nil, act("fs_remove", plan.Dangerous, map[string]string{"path": "/tmp/x"}), Confirm},
		{"fs_remove outside tmp", nil, act("fs_remove", plan.Dangerous, map[string]string{"path": "/etc"}), Deny},
		{"fs_remove tmp root", nil, act("fs_remove", plan.Dangerous, map[string]string{"path": "/tmp/"}), Deny},
		{"deny ssh port", nil, act("fw_deny", plan.Change, map[string]string{"port": "22", "ssh_port": "22"}), Deny},
		{"deny ssh port from one ip", nil, act("fw_deny", plan.Change, map[string]string{"port": "22", "ssh_port": "22", "from": "10.0.0.5"}), Allow},
		{"enable without ssh rule", nil, act("fw_enable", plan.Change, map[string]string{"ssh_port": "2222", "ssh_allowed": "false"}), Deny},
		{"enable with ssh rule", nil, act("fw_enable", plan.Change, map[string]string{"ssh_port": "22", "ssh_allowed": "true"}), Allow},
		{"lock login user", nil, act("user_lock", plan.Change, map[string]string{"user": "deploy", "login_user": "deploy"}), Deny},
		{"lock other user", nil, act("user_lock", plan.Change, map[string]string{"user": "bob", "login_user": "deploy"}), Allow},
		{"last key", nil, act("key_remove", plan.Change, map[string]string{"user": "deploy", "login_user": "deploy", "remaining_keys": "0"}), Deny},
		{"root login off as root", nil, act("sshd_set", plan.Change, map[string]string{"login_user": "root", "sshd.permitrootlogin": "no"}), Deny},
		{"allowusers drops me", nil, act("sshd_set", plan.Change, map[string]string{"login_user": "deploy", "sshd.allowusers": "alice bob"}), Deny},
		{"allowusers keeps me", nil, act("sshd_set", plan.Change, map[string]string{"login_user": "deploy", "sshd.allowusers": "alice deploy"}), Allow},
		{"protected path", nil, act("fs_write", plan.Change, nil, func(a *plan.Action) { a.Steps = []plan.Step{plan.Write("/etc/fstab", "", "0644")} }), Deny},
		{"tainted", nil, act("key_add", plan.Change, nil, func(a *plan.Action) { a.Taint = []plan.TaintSource{{Arg: "key", Value: "x", Source: "host output"}} }), Confirm},
		{"prod with --yes", func(c Context) Context { c.AutoApprove = true; return c }, act("svc_control", plan.Change, nil), Confirm},
		{"irreversible", nil, act("pkg_upgrade", plan.Change, nil, func(a *plan.Action) { a.Risk = []plan.Risk{plan.RiskIrreversible} }), Confirm},
	}
	e := New()
	for _, tt := range tests {
		c := base
		if tt.ctx != nil {
			c = tt.ctx(c)
		}
		if got := e.Evaluate(c, tt.a).Decision; got != tt.want {
			t.Errorf("%s: got %s, want %s (%+v)", tt.name, got, tt.want, e.Evaluate(c, tt.a).Reasons)
		}
	}
}

func TestEnableAllowedEarlierInPlan(t *testing.T) {
	allow := act("fw_allow", plan.Change, map[string]string{"port": "22"}, func(a *plan.Action) { a.ID = "a1" })
	enable := act("fw_enable", plan.Change, map[string]string{"ssh_port": "22", "ssh_allowed": "false"}, func(a *plan.Action) { a.ID = "a2" })
	e := New()
	worst, _ := e.EvaluatePlan(Context{MaxTier: plan.Change}, &plan.Plan{Actions: []plan.Action{allow, enable}})
	if worst != Allow {
		t.Errorf("allow-then-enable should pass, got %s", worst)
	}
	worst, _ = e.EvaluatePlan(Context{MaxTier: plan.Change}, &plan.Plan{Actions: []plan.Action{enable, allow}})
	if worst != Deny {
		t.Errorf("enable-then-allow should be denied, got %s", worst)
	}
}

func TestUserRules(t *testing.T) {
	rules, err := Parse([]byte(`
rules:
  - id: no-prod-reboot
    decision: deny
    tools: [host_reboot]
    tags: [prod]
  - id: review-pkgs
    decision: confirm
    tools: ["pkg_*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	e := New(rules...)
	c := Context{MaxTier: plan.Dangerous, HostTags: map[string][]string{"web-1": {"prod"}, "dev-1": nil}}
	if d := e.Evaluate(c, act("host_reboot", plan.Dangerous, nil)).Decision; d != Deny {
		t.Errorf("prod reboot = %s", d)
	}
	devReboot := act("host_reboot", plan.Dangerous, nil, func(a *plan.Action) { a.Host = "dev-1" })
	if d := e.Evaluate(c, devReboot).Decision; d != Confirm {
		t.Errorf("dev reboot = %s; want confirm (dangerous)", d)
	}
	if d := e.Evaluate(c, act("pkg_install", plan.Change, nil)).Decision; d != Confirm {
		t.Errorf("pkg_install = %s", d)
	}

	for _, bad := range []string{
		"rules:\n  - id: x\n    decision: allow\n",
		"rules:\n  - decision: deny\n",
		"rules:\n  - id: x\n    decision: deny\n    tiers: [root]\n",
		"rules:\n  - id: x\n    decision: deny\n    tool: [x]\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
	if r, err := Parse([]byte(Skeleton)); err != nil || len(r) != 0 {
		t.Errorf("skeleton should parse to no rules: %v %v", r, err)
	}
}

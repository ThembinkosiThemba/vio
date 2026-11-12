package change

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ThembinkosiThemba/vio/internal/facts"
	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/tools"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

const sshdBefore = `Include /etc/ssh/sshd_config.d/*.conf
#PermitRootLogin prohibit-password
PasswordAuthentication yes
X11Forwarding yes
Match User backup
    PasswordAuthentication yes
`

// testHost is an Ubuntu host as root's sudo user "deploy". files are served
// by the stat/read scripts; other commands come from cmds (keyed by argv
// joined with spaces, without sudo).
func testHost(files map[string]string, cmds map[string]string) (*tools.Host, *transport.Fake) {
	f := &transport.Fake{Handler: func(c transport.Cmd) (transport.Result, error) {
		a := c.Args
		ok := func(s string) (transport.Result, error) { return transport.Result{Stdout: []byte(s)}, nil }
		if a[0] == "sh" && len(a) >= 5 {
			if body, exists := files[a[4]]; strings.HasPrefix(a[2], "[ -e \"$1\" ] || [ -L") && len(a) == 5 {
				if !exists {
					return transport.Result{ExitCode: 44}, nil
				}
				return ok("100 81a4 1700000000")
			} else if strings.HasPrefix(a[2], "[ -e \"$1\" ] || exit 44") {
				if !exists {
					return transport.Result{ExitCode: 44}, nil
				}
				return ok(body)
			}
		}
		if a[0] == "stat" {
			return ok("644 root:root\n")
		}
		if out, has := cmds[strings.Join(a, " ")]; has {
			return ok(out)
		}
		for k, out := range cmds {
			if strings.HasSuffix(k, "*") && strings.HasPrefix(strings.Join(a, " "), strings.TrimSuffix(k, "*")) {
				return ok(out)
			}
		}
		return transport.Result{ExitCode: 1, Stderr: []byte("unhandled: " + strings.Join(a, " "))}, nil
	}}
	h := &tools.Host{Name: "web-1", X: f, Facts: facts.Facts{
		Basic: facts.Basic{User: "deploy", Sudo: true}, Init: "systemd", PkgMgr: "apt",
		Firewall: "ufw", SSHUnit: "ssh", SSHPort: 22, ClientIP: "198.51.100.7",
	}}
	return h, f
}

func planOf(t *testing.T, tl tools.Tool, h *tools.Host, args string) plan.Action {
	t.Helper()
	a, err := tl.(tools.ChangeTool).Plan(context.Background(), h, json.RawMessage(args))
	if err != nil {
		t.Fatalf("%s.Plan(%s): %v", tl.Name(), args, err)
	}
	return a
}

func argvs(a plan.Action) []string {
	var out []string
	for _, s := range a.Steps {
		if s.Kind == "run" {
			out = append(out, strings.Join(s.Args, " "))
		} else {
			out = append(out, "write "+s.Path)
		}
	}
	return out
}

func TestSetSSHDirectives(t *testing.T) {
	got := SetSSHDirectives(sshdBefore, map[string]string{"PasswordAuthentication": "no", "PermitRootLogin": "no"})
	want := managedHeader + `
PasswordAuthentication no
PermitRootLogin no
Include /etc/ssh/sshd_config.d/*.conf
#PermitRootLogin prohibit-password
X11Forwarding yes
Match User backup
    PasswordAuthentication yes
`
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	// Idempotent: applying the same settings again changes nothing.
	if again := SetSSHDirectives(got, map[string]string{"PasswordAuthentication": "no", "PermitRootLogin": "no"}); again != got {
		t.Errorf("not idempotent:\n%s", again)
	}
}

func TestSSHDSetPlan(t *testing.T) {
	h, f := testHost(map[string]string{"/etc/ssh/sshd_config": sshdBefore}, nil)
	a := planOf(t, sshdSet, h, `{"settings":{"passwordauthentication":"no"}}`)
	if !a.Has(plan.RiskLockout) {
		t.Error("sshd_set must carry the lockout risk")
	}
	want := []string{"write /etc/ssh/sshd_config", "sshd -t", "systemctl try-reload-or-restart -- ssh"}
	if !slices.Equal(argvs(a), want) {
		t.Errorf("steps = %v", argvs(a))
	}
	if !strings.Contains(a.Diff, "-PasswordAuthentication yes") || !strings.Contains(a.Diff, "+PasswordAuthentication no") {
		t.Errorf("diff:\n%s", a.Diff)
	}
	if !slices.Equal(a.Rollback.Restore, []string{"/etc/ssh/sshd_config"}) || len(a.Preconditions) != 1 {
		t.Errorf("rollback/preconditions: %+v %+v", a.Rollback, a.Preconditions)
	}
	if a.Meta["sshd.passwordauthentication"] != "no" || a.Meta["login_user"] != "deploy" {
		t.Errorf("meta = %v", a.Meta)
	}
	for _, c := range f.Calls {
		if strings.Contains(c, "mv -f") || strings.Contains(c, "reload") {
			t.Errorf("Plan must not mutate the host, ran: %s", c)
		}
	}
	if _, err := sshdSet.Plan(context.Background(), h, json.RawMessage(`{"settings":{"Port":"2222"}}`)); err == nil {
		t.Error("Port must be refused")
	}
}

func TestFwAllowPlanAndRollback(t *testing.T) {
	h, f := testHost(nil, map[string]string{"ufw delete allow proto tcp from any to any port 443": ""})
	a := planOf(t, fwRule("fw_allow", "allow"), h, `{"port":443}`)
	if !slices.Equal(argvs(a), []string{"ufw allow proto tcp from any to any port 443"}) {
		t.Errorf("steps = %v", argvs(a))
	}
	a.ID = "a1"
	if err := (tools.Steps{}).Rollback(context.Background(), h, a); err != nil {
		t.Fatal(err)
	}
	if len(f.CallsMatching("sudo -n -- ufw delete allow proto tcp from any to any port 443")) != 1 {
		t.Errorf("rollback should delete the rule as root: %v", f.Calls)
	}
}

func TestSvcControlPlan(t *testing.T) {
	h, _ := testHost(nil, map[string]string{"sh -c *": "inactive enabled\n"})
	a := planOf(t, svcControl, h, `{"name":"nginx","action":"start"}`)
	if !slices.Equal(argvs(a), []string{"systemctl start -- nginx"}) || !slices.Equal(a.Rollback.Commands[0], []string{"systemctl", "stop", "--", "nginx"}) {
		t.Errorf("steps %v rollback %v", argvs(a), a.Rollback.Commands)
	}
	if _, err := svcControl.Plan(context.Background(), h, json.RawMessage(`{"name":"nginx","action":"stop"}`)); err == nil {
		t.Error("stopping an inactive service should be refused")
	}
	if _, err := svcControl.Plan(context.Background(), h, json.RawMessage(`{"name":"-x","action":"start"}`)); err == nil {
		t.Error("a flag-like name should be refused")
	}
	h2, _ := testHost(nil, map[string]string{"sh -c *": "active enabled\n"})
	if a := planOf(t, svcControl, h2, `{"name":"ssh","action":"restart"}`); !a.Has(plan.RiskLockout) {
		t.Error("restarting ssh carries lockout risk")
	}
}

func TestKeyAddPlan(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@laptop"
	h, _ := testHost(map[string]string{"/home/alice/.ssh/authorized_keys": ""}, map[string]string{
		"getent passwd -- alice": "alice:x:1001:1001::/home/alice:/bin/bash\n",
		"id -gn -- alice":        "alice\n",
	})
	a := planOf(t, keyAdd, h, `{"user":"alice","key":"`+key+`"}`)
	w := a.Steps[1]
	if w.Kind != "write" || w.Path != "/home/alice/.ssh/authorized_keys" || w.Content != key+"\n" {
		t.Errorf("write step = %+v", w)
	}
	if _, err := keyAdd.Plan(context.Background(), h, json.RawMessage(`{"user":"alice","key":"not a key"}`)); err == nil {
		t.Error("invalid key accepted")
	}
	if _, err := keyAdd.Plan(context.Background(), h, json.RawMessage(`{"user":"alice","key":"`+key+`\n`+key+`"}`)); err == nil {
		t.Error("two keys accepted")
	}
}

func TestFsPatchAndValidators(t *testing.T) {
	conf := "server {\n  listen 80;\n}\n"
	h, _ := testHost(map[string]string{"/etc/nginx/sites-enabled/app": conf}, nil)
	a := planOf(t, fsPatch, h, `{"path":"/etc/nginx/sites-enabled/app","old":"listen 80;","new":"listen 8080;","reload":"nginx"}`)
	want := []string{"write /etc/nginx/sites-enabled/app", "nginx -t", "systemctl reload-or-restart -- nginx"}
	if !slices.Equal(argvs(a), want) {
		t.Errorf("steps = %v", argvs(a))
	}
	if a.Steps[0].Content != "server {\n  listen 8080;\n}\n" || a.Steps[0].Mode != "0644" {
		t.Errorf("write = %+v", a.Steps[0])
	}
	for _, bad := range []string{
		`{"path":"/etc/nginx/sites-enabled/app","old":"nope","new":"x"}`,
		`{"path":"/etc/shadow","old":"a","new":"b"}`,
		`{"path":"etc/x","old":"a","new":"b"}`,
	} {
		if _, err := fsPatch.Plan(context.Background(), h, json.RawMessage(bad)); err == nil {
			t.Errorf("fs_patch %s should fail", bad)
		}
	}
}

func TestPkgInstallSkipsInstalled(t *testing.T) {
	h, _ := testHost(nil, map[string]string{
		"dpkg-query -W -f=${Package}\t${Version}\t${db:Status-Abbrev}\n -- curl fail2ban": "curl\t8.5.0\tii \n",
	})
	a := planOf(t, pkgInstall, h, `{"names":["curl","fail2ban"]}`)
	if a.Summary != "install fail2ban" || !strings.HasSuffix(argvs(a)[1], "-- fail2ban") {
		t.Errorf("summary %q steps %v", a.Summary, argvs(a))
	}
	if !slices.Contains(a.Rollback.Commands[0], "remove") || a.Rollback.Commands[0][len(a.Rollback.Commands[0])-1] != "fail2ban" {
		t.Errorf("rollback = %v", a.Rollback.Commands)
	}
}

func TestShellExecIsIrreversible(t *testing.T) {
	h, _ := testHost(nil, nil)
	a := planOf(t, shellExec, h, `{"command":["touch","/srv/x"],"reason":"test"}`)
	if !a.Has(plan.RiskIrreversible) || a.Tier != plan.Dangerous || !a.Rollback.Empty() {
		t.Errorf("shell_exec = %+v", a)
	}
}

func TestPlanNeedsPrivilege(t *testing.T) {
	h, _ := testHost(nil, nil)
	h.Facts.Sudo = false
	if _, err := fwEnable.Plan(context.Background(), h, nil); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Errorf("want a privilege error, got %v", err)
	}
}

func TestEveryChangeToolHasValidSchema(t *testing.T) {
	seen := map[string]bool{}
	for _, tl := range All() {
		var s map[string]any
		if err := json.Unmarshal(tl.Schema(), &s); err != nil || s["type"] != "object" {
			t.Errorf("%s: bad schema: %v", tl.Name(), err)
		}
		if tl.Tier() < plan.Change {
			t.Errorf("%s: change tools must be change or dangerous tier", tl.Name())
		}
		if _, ok := tl.(tools.ChangeTool); !ok {
			t.Errorf("%s does not implement ChangeTool", tl.Name())
		}
		if seen[tl.Name()] {
			t.Errorf("duplicate %s", tl.Name())
		}
		seen[tl.Name()] = true
	}
}

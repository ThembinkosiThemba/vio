package apply

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/facts"
	"github.com/ThembinkosiThemba/vio/internal/guard"
	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/policy"
	"github.com/ThembinkosiThemba/vio/internal/tools"
	"github.com/ThembinkosiThemba/vio/internal/tools/change"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

type rig struct {
	fake    *transport.Fake
	env     *Env
	records []audit.Record
	freshOK bool
}

// newRig answers every command with exit 0 unless fail matches the command line.
func newRig(t *testing.T, fail func(line string) (transport.Result, bool)) *rig {
	r := &rig{freshOK: true}
	r.fake = &transport.Fake{Handler: func(c transport.Cmd) (transport.Result, error) {
		line := transport.CommandLine(c)
		if fail != nil {
			if res, ok := fail(line); ok {
				return res, nil
			}
		}
		return transport.Result{}, nil
	}}
	h := &tools.Host{Name: "web-1", X: r.fake, Facts: facts.Facts{Basic: facts.Basic{User: "deploy", Sudo: true}, Init: "systemd"}}
	r.env = &Env{
		Host: func(context.Context, string) (*tools.Host, error) { return h, nil },
		Fresh: func(context.Context, string) (transport.Executor, error) {
			if !r.freshOK {
				return nil, errors.New("connection refused")
			}
			return &transport.Fake{Responses: map[string]transport.Result{"true": {}}}, nil
		},
		Tools:       tools.NewRegistry(change.All()...),
		Policy:      policy.New(),
		PolicyCtx:   policy.Context{MaxTier: plan.Dangerous},
		Record:      func(a audit.Record) error { r.records = append(r.records, a); return nil },
		GuardWindow: 30 * time.Second,
		StateDir:    t.TempDir(),
	}
	return r
}

func approved(t *testing.T, actions ...plan.Action) *plan.Plan {
	t.Helper()
	p, err := plan.New("test", actions)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Approve("op", plan.Dangerous); err != nil {
		t.Fatal(err)
	}
	return p
}

func sshdAction() plan.Action {
	return plan.Action{
		Host: "web-1", Tool: "sshd_set", Tier: plan.Change, Summary: "sshd PasswordAuthentication=no",
		Args:          []byte(`{}`),
		Steps:         []plan.Step{plan.Write("/etc/ssh/sshd_config", "PasswordAuthentication no\n", "0644"), plan.Run("validate", "sshd", "-t"), plan.Run("reload", "systemctl", "reload", "ssh")},
		Preconditions: []plan.Precondition{{Desc: "unchanged", Args: []string{"hash"}, Want: ""}},
		Rollback:      &plan.RollbackSpec{Restore: []string{"/etc/ssh/sshd_config"}, Commands: [][]string{{"systemctl", "reload", "ssh"}}},
		Verify:        []plan.Probe{{Kind: plan.ProbeCmd, Desc: "sshd -T", Args: []string{"sshd", "-T"}}},
		Risk:          []plan.Risk{plan.RiskLockout},
	}
}

func TestApplyGuardedSuccess(t *testing.T) {
	r := newRig(t, nil)
	rep, err := Apply(context.Background(), r.env, approved(t, sshdAction()))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Code != CodeOK || rep.Outcomes[0].Status != "applied" {
		t.Fatalf("report = %+v", rep)
	}
	order := []string{"sh -c", "systemd-run", "sshd -t", "systemctl reload ssh", "sshd -T", "systemctl stop vio-guard-"}
	last := -1
	for _, want := range order {
		idx := -1
		for i, c := range r.fake.Calls {
			if i > last && strings.Contains(c, want) {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Fatalf("missing %q after call %d in:\n%s", want, last, strings.Join(r.fake.Calls, "\n"))
		}
		last = idx
	}
	if rec, err := LoadRecord(r.env.StateDir, rep.ID); err != nil || rec.Outcomes[0].Status != "applied" {
		t.Errorf("apply record: %v %+v", err, rec)
	}
}

func TestApplyDriftChangesNothing(t *testing.T) {
	r := newRig(t, func(line string) (transport.Result, bool) {
		if strings.HasSuffix(line, "hash") {
			return transport.Result{Stdout: []byte("something-else\n")}, true
		}
		return transport.Result{}, false
	})
	rep, err := Apply(context.Background(), r.env, approved(t, sshdAction()))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Code != CodeDrift || rep.Outcomes[0].Status != "skipped" {
		t.Errorf("report = %+v", rep)
	}
	if c := r.fake.CallsMatching("systemd-run"); len(c) != 0 {
		t.Error("nothing may happen after drift")
	}
}

func TestApplyVerifyFailureRollsBack(t *testing.T) {
	r := newRig(t, func(line string) (transport.Result, bool) {
		if strings.HasSuffix(line, "sshd -T") {
			return transport.Result{ExitCode: 255}, true
		}
		return transport.Result{}, false
	})
	rep, err := Apply(context.Background(), r.env, approved(t, sshdAction()))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Code != CodeReverted || rep.Outcomes[0].Status != "rolled_back" {
		t.Fatalf("report = %+v", rep)
	}
	restored := false
	for _, c := range r.fake.Calls {
		if strings.Contains(c, "rrc") && strings.Contains(c, "/var/lib/vio/backups/"+rep.ID+"/a1") {
			restored = true
		}
	}
	if !restored {
		t.Errorf("backup was not restored:\n%s", strings.Join(r.fake.Calls, "\n"))
	}
	if len(r.fake.CallsMatching("systemctl stop vio-guard-")) != 1 {
		t.Error("guard should be disarmed after a successful manual rollback")
	}
}

func TestApplyFailedStepStopsPlan(t *testing.T) {
	r := newRig(t, func(line string) (transport.Result, bool) {
		if strings.HasSuffix(line, "sshd -t") {
			return transport.Result{ExitCode: 1, Stderr: []byte("bad option")}, true
		}
		return transport.Result{}, false
	})
	second := plan.Action{Host: "web-1", Tool: "svc_control", Tier: plan.Change, Summary: "start x", Args: []byte(`{}`),
		Steps: []plan.Step{plan.Run("start", "systemctl", "start", "x")}, Rollback: &plan.RollbackSpec{Commands: [][]string{{"systemctl", "stop", "x"}}}}
	rep, err := Apply(context.Background(), r.env, approved(t, sshdAction(), second))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Outcomes[0].Status != "rolled_back" || rep.Outcomes[1].Status != "skipped" {
		t.Errorf("outcomes = %+v", rep.Outcomes)
	}
	if len(r.fake.CallsMatching("systemctl start x")) != 0 {
		t.Error("later actions must not run after a failure")
	}
}

func TestApplyRefusesUnapprovedOrTampered(t *testing.T) {
	r := newRig(t, nil)
	p, _ := plan.New("x", []plan.Action{sshdAction()})
	if _, err := Apply(context.Background(), r.env, p); !errors.Is(err, ErrNotApproved) {
		t.Errorf("unapproved: %v", err)
	}
	p = approved(t, sshdAction())
	p.Actions[0].Steps[1].Args = []string{"rm", "-rf", "/"}
	if _, err := Apply(context.Background(), r.env, p); !errors.Is(err, plan.ErrTampered) {
		t.Errorf("tampered: %v", err)
	}
	if len(r.fake.Calls) != 0 {
		t.Errorf("nothing may run: %v", r.fake.Calls)
	}
}

func TestApplyRechecksPolicy(t *testing.T) {
	r := newRig(t, nil)
	r.env.PolicyCtx.MaxTier = plan.Observe
	rep, err := Apply(context.Background(), r.env, approved(t, sshdAction()))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Code != CodePolicy || len(r.fake.Calls) != 0 {
		t.Errorf("policy must be re-checked before running: %+v %v", rep, r.fake.Calls)
	}
}

func TestRevertScript(t *testing.T) {
	a := sshdAction()
	a.ID = "a1"
	s := guard.RevertScript(a, "/var/lib/vio/backups/x-1/a1", "g1")
	for _, want := range []string{"restore /var/lib/vio/backups/x-1/a1 /etc/ssh/sshd_config", "systemctl reload ssh || rc=1", "touch /var/lib/vio/guards/g1/reverted"} {
		if !strings.Contains(s, want) {
			t.Errorf("revert script missing %q:\n%s", want, s)
		}
	}
	a.Rollback.Commands = [][]string{{"echo", "a'; rm -rf /; '"}}
	if s := guard.RevertScript(a, "/d", ""); !strings.Contains(s, `'a'\''; rm -rf /; '\'''`) {
		t.Errorf("values must be quoted:\n%s", s)
	}
}

// Package apply runs approved plans. It is deterministic: the model is not in
// this loop. Per action: re-check policy → preconditions → backup → arm guard
// (lockout risk) → execute → verify → disarm, or roll back. See specs/plan.md §5.10.
package apply

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/fsutil"
	"github.com/ThembinkosiThemba/vio/internal/guard"
	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/policy"
	"github.com/ThembinkosiThemba/vio/internal/redact"
	"github.com/ThembinkosiThemba/vio/internal/tools"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

// BackupDir holds per-apply backups on the host.
const BackupDir = "/var/lib/vio/backups"

// Exit codes the engine can produce (specs/plan.md §5.1).
const (
	CodeOK       = 0
	CodeError    = 1
	CodePolicy   = 3
	CodeDrift    = 5
	CodeReverted = 6
)

// Env is what the engine needs from the rest of vio.
type Env struct {
	// Host returns the session's connection to a host, with facts.
	Host func(ctx context.Context, name string) (*tools.Host, error)
	// Fresh opens a brand-new SSH connection, used to prove access still works.
	Fresh     func(ctx context.Context, name string) (transport.Executor, error)
	Tools     *tools.Registry
	Policy    *policy.Engine
	PolicyCtx policy.Context
	Record    func(audit.Record) error
	// Progress receives human-readable progress; may be nil.
	Progress    func(Event)
	GuardWindow time.Duration
	// Atomic rolls back earlier successful actions when a later one fails.
	Atomic bool
	// StateDir is where apply records are kept for `vio rollback`.
	StateDir string
}

// Event is a progress update.
type Event struct {
	Action *plan.Action
	Phase  string // start | guard | verify | done | failed | rollback | reverted | wait
	Msg    string
}

// Record is the local record of an apply, kept for `vio rollback`.
type Record struct {
	ID       string         `json:"id"`
	At       time.Time      `json:"at"`
	Plan     *plan.Plan     `json:"plan"`
	Outcomes []plan.Outcome `json:"outcomes"`
}

// Report is the result of Apply.
type Report struct {
	Record
	Code int
}

// ErrNotApproved means the plan has no valid approval.
var ErrNotApproved = errors.New("plan is not approved")

func (e *Env) emit(a *plan.Action, phase, format string, args ...any) {
	if e.Progress != nil {
		e.Progress(Event{Action: a, Phase: phase, Msg: fmt.Sprintf(format, args...)})
	}
}

func (e *Env) record(r audit.Record) error {
	if e.Record == nil {
		return nil
	}
	if err := e.Record(r); err != nil {
		return fmt.Errorf("audit log unavailable, stopping: %w", err)
	}
	return nil
}

func newID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "x-" + hex.EncodeToString(b[:])
}

// Apply executes an approved plan. It stops at the first failed action.
func Apply(ctx context.Context, e *Env, p *plan.Plan) (*Report, error) {
	if err := p.CheckIntegrity(); err != nil {
		return nil, err
	}
	if p.Approval == nil {
		return nil, ErrNotApproved
	}
	if p.MaxTier() > p.Approval.MaxTier {
		return nil, fmt.Errorf("plan needs %s tier but was approved for %s", p.MaxTier(), p.Approval.MaxTier)
	}
	rep := &Report{Record: Record{ID: newID(), At: time.Now().UTC(), Plan: p}}
	args, _ := json.Marshal(map[string]string{"plan": p.ID, "hash": p.Hash, "apply": rep.ID})
	if err := e.record(audit.Record{Kind: audit.KindApply, Tool: "plan", Args: args, Msg: "apply started"}); err != nil {
		return nil, err
	}
	defer func() { _ = e.save(rep) }()

	pc := e.PolicyCtx
	pc.Plan = p
	var done []int // indexes of applied actions
	for i := range p.Actions {
		a := &p.Actions[i]
		code, out := e.applyOne(ctx, pc, rep.ID, a)
		rep.Outcomes = append(rep.Outcomes, out)
		if code == CodeOK {
			done = append(done, i)
			continue
		}
		rep.Code = code
		for _, b := range p.Actions[i+1:] {
			rep.Outcomes = append(rep.Outcomes, plan.Outcome{ActionID: b.ID, Status: "skipped", Message: "an earlier action failed"})
		}
		if e.Atomic {
			slices.Reverse(done)
			for _, j := range done {
				b := &p.Actions[j]
				e.emit(b, "rollback", "rolling back %s (atomic)", b.ID)
				status := "rolled_back"
				if err := e.rollbackOne(ctx, rep.ID, b); err != nil {
					status = "rollback_failed"
				}
				rep.Outcomes[j].Status = status
			}
		}
		break
	}
	return rep, nil
}

// applyOne runs a single action and returns an exit code and its outcome.
func (e *Env) applyOne(ctx context.Context, pc policy.Context, applyID string, a *plan.Action) (int, plan.Outcome) {
	fail := func(code int, status, format string, args ...any) (int, plan.Outcome) {
		msg := fmt.Sprintf(format, args...)
		e.emit(a, "failed", "%s", msg)
		ex := code
		_ = e.record(audit.Record{Kind: audit.KindApply, Host: a.Host, Tool: a.Tool, Msg: a.ID + " " + status + ": " + msg, Exit: &ex})
		return code, plan.Outcome{ActionID: a.ID, Status: status, Message: msg}
	}
	e.emit(a, "start", "%s", a.Summary)

	// 1. Policy, again, right before execution.
	if r := e.Policy.Evaluate(pc, *a); r.Decision == policy.Deny {
		return fail(CodePolicy, "skipped", "policy denied: %s", r.Reasons[len(r.Reasons)-1].Msg)
	}
	t, ok := e.Tools.Get(a.Tool)
	ct, isChange := t.(tools.ChangeTool)
	if !ok || !isChange || t.Tier() != a.Tier {
		return fail(CodeError, "skipped", "unknown change tool %q", a.Tool)
	}
	h, err := e.Host(ctx, a.Host)
	if err != nil {
		return fail(CodeError, "skipped", "%v", err)
	}
	root := h.Root()

	// 2. Preconditions: nothing has changed yet if these fail.
	for _, pre := range a.Preconditions {
		res, err := root.Run(ctx, transport.Cmd{Args: pre.Args})
		if err != nil {
			return fail(CodeError, "skipped", "precondition %q: %v", pre.Desc, err)
		}
		if got := strings.TrimSpace(string(res.Stdout)); got != pre.Want {
			return fail(CodeDrift, "skipped", "drift: %s no longer holds (re-plan)", pre.Desc)
		}
	}

	// 3. Backups.
	bdir := backupDir(applyID, a.ID)
	if a.Rollback != nil && len(a.Rollback.Restore) > 0 {
		argv := append([]string{"sh", "-c", guard.BackupScript, "sh", bdir}, a.Rollback.Restore...)
		if err := tools.RunSteps(ctx, root, []plan.Step{plan.Run("backup", argv...)}); err != nil {
			return fail(CodeError, "skipped", "backup: %v", err)
		}
	}

	// 4. Guard.
	var g *guard.Guard
	if a.Has(plan.RiskLockout) {
		gid := applyID[2:] + "-" + a.ID
		g, err = guard.Arm(ctx, root, gid, guard.RevertScript(*a, bdir, gid), e.GuardWindow, h.Facts.Init == "systemd")
		if err != nil {
			return fail(CodeError, "skipped", "%v (refusing a lockout-risk change without a guard)", err)
		}
		e.emit(a, "guard", "guard armed (%s, reverts in %s unless a fresh login works)", g.Unit(), g.Window)
	}

	// 5. Execute.
	_ = e.record(audit.Record{Kind: audit.KindApply, Host: a.Host, Tool: a.Tool, Args: redact.JSON(a.Args), Msg: a.ID + " executing: " + a.Summary})
	if _, err := ct.Apply(ctx, h, *a); err != nil {
		return e.recover(ctx, applyID, a, ct, h, g, "apply failed: "+err.Error(), CodeError)
	}

	// 6. Verify.
	probes := slices.Clone(a.Verify)
	if a.Has(plan.RiskLockout) {
		probes = append(probes, plan.Probe{Kind: plan.ProbeSSHLogin, Desc: "fresh SSH login"})
	}
	for _, pr := range probes {
		if err := e.probe(ctx, h, a.Host, pr); err != nil {
			return e.recover(ctx, applyID, a, ct, h, g, "verify failed: "+pr.Desc+": "+err.Error(), CodeReverted)
		}
		e.emit(a, "verify", "%s ✓", pr.Desc)
	}
	ok0 := 0
	_ = e.record(audit.Record{Kind: audit.KindVerify, Host: a.Host, Tool: a.Tool, Msg: a.ID + " verified", Exit: &ok0})

	// 7. Disarm.
	if g != nil {
		if err := g.Disarm(ctx, root); err != nil {
			// The change works but the guard will revert it: say so plainly.
			return fail(CodeError, "failed", "applied and verified, but disarming the guard failed, so the host will revert in %s: %v", g.Window, err)
		}
	}
	e.emit(a, "done", "%s", a.Summary)
	_ = e.record(audit.Record{Kind: audit.KindApply, Host: a.Host, Tool: a.Tool, Msg: a.ID + " applied", Exit: &ok0})
	return CodeOK, plan.Outcome{ActionID: a.ID, Status: "applied"}
}

// recover undoes a failed action. It first tries the live session; if that
// fails and a guard is armed, it waits for the host to revert itself.
func (e *Env) recover(ctx context.Context, applyID string, a *plan.Action, ct tools.ChangeTool, h *tools.Host, g *guard.Guard, why string, code int) (int, plan.Outcome) {
	e.emit(a, "rollback", "%s; rolling back", why)
	err := e.restore(ctx, h, applyID, a)
	if err == nil {
		err = ct.Rollback(ctx, h, *a)
	}
	if err == nil && g != nil {
		// Rolled back by hand: prove access, then cancel the timer.
		if perr := e.probe(ctx, h, a.Host, plan.Probe{Kind: plan.ProbeSSHLogin}); perr != nil {
			err = perr
		} else {
			err = g.Disarm(ctx, h.Root())
		}
	}
	if err == nil {
		ex := code
		_ = e.record(audit.Record{Kind: audit.KindRollback, Host: a.Host, Tool: a.Tool, Msg: a.ID + " rolled back: " + why, Exit: &ex})
		e.emit(a, "reverted", "rolled back")
		return code, plan.Outcome{ActionID: a.ID, Status: "rolled_back", Message: why}
	}
	if g == nil {
		ex := CodeError
		_ = e.record(audit.Record{Kind: audit.KindRollback, Host: a.Host, Tool: a.Tool, Msg: a.ID + " rollback failed: " + err.Error(), Exit: &ex})
		return CodeError, plan.Outcome{ActionID: a.ID, Status: "rollback_failed", Message: why + "; rollback failed: " + err.Error()}
	}
	// The session can't fix it: wait for the dead-man switch, then confirm.
	e.emit(a, "wait", "can't roll back over this connection (%v); waiting %s for the host to revert itself", err, g.Window)
	select {
	case <-time.After(g.Window + 15*time.Second):
	case <-ctx.Done():
		return CodeReverted, plan.Outcome{ActionID: a.ID, Status: "failed", Message: why + "; interrupted while waiting for the guard to revert"}
	}
	x, ferr := e.Fresh(ctx, a.Host)
	if ferr != nil {
		ex := CodeReverted
		_ = e.record(audit.Record{Kind: audit.KindRollback, Host: a.Host, Tool: a.Tool, Msg: a.ID + " guard window passed but host still unreachable", Exit: &ex})
		return CodeReverted, plan.Outcome{ActionID: a.ID, Status: "failed", Message: why + "; host still unreachable after the guard window: " + ferr.Error()}
	}
	defer x.Close()
	ex := CodeReverted
	msg := "reverted by guard"
	if !guard.Reverted(ctx, transport.Elevated(x), g.ID) {
		msg = "reachable again, but the guard's revert marker is missing"
	}
	_ = e.record(audit.Record{Kind: audit.KindRollback, Host: a.Host, Tool: a.Tool, Msg: a.ID + " " + msg, Exit: &ex})
	e.emit(a, "reverted", "%s", msg)
	return CodeReverted, plan.Outcome{ActionID: a.ID, Status: "reverted", Message: why + "; " + msg}
}

func backupDir(applyID, actionID string) string { return BackupDir + "/" + applyID + "/" + actionID }

// restore puts a's backed-up files back.
func (e *Env) restore(ctx context.Context, h *tools.Host, applyID string, a *plan.Action) error {
	if a.Rollback == nil || len(a.Rollback.Restore) == 0 {
		return nil
	}
	argv := append([]string{"sh", "-c", guard.RestoreScript, "sh", backupDir(applyID, a.ID)}, a.Rollback.Restore...)
	return tools.RunSteps(ctx, h.Root(), []plan.Step{plan.Run("restore backups", argv...)})
}

func (e *Env) rollbackOne(ctx context.Context, applyID string, a *plan.Action) error {
	h, err := e.Host(ctx, a.Host)
	if err != nil {
		return err
	}
	t, _ := e.Tools.Get(a.Tool)
	ct, ok := t.(tools.ChangeTool)
	if !ok {
		return fmt.Errorf("unknown change tool %q", a.Tool)
	}
	if err := e.restore(ctx, h, applyID, a); err != nil {
		return err
	}
	err = ct.Rollback(ctx, h, *a)
	ex := 0
	msg := a.ID + " rolled back"
	if err != nil {
		ex, msg = 1, a.ID+" rollback failed: "+err.Error()
	}
	_ = e.record(audit.Record{Kind: audit.KindRollback, Host: a.Host, Tool: a.Tool, Msg: msg, Exit: &ex})
	return err
}

func (e *Env) probe(ctx context.Context, h *tools.Host, host string, p plan.Probe) error {
	switch p.Kind {
	case plan.ProbeSSHLogin:
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		x, err := e.Fresh(pctx, host)
		if err != nil {
			return err
		}
		defer x.Close()
		res, err := x.Run(pctx, transport.Cmd{Args: []string{"true"}})
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("`true` exited %d", res.ExitCode)
		}
		return nil
	case plan.ProbeCmd:
		res, err := h.Root().Run(ctx, transport.Cmd{Args: p.Args, Timeout: time.Minute})
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("%s exited %d", p.Args[0], res.ExitCode)
		}
		if p.Want != "" && !strings.Contains(strings.ToLower(string(res.Stdout)), strings.ToLower(p.Want)) {
			return fmt.Errorf("output does not contain %q", p.Want)
		}
		return nil
	}
	return fmt.Errorf("unknown probe kind %q", p.Kind)
}

func (e *Env) save(r *Report) error {
	if e.StateDir == "" {
		return nil
	}
	b, err := json.MarshalIndent(r.Record, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(e.StateDir, "applies", r.ID+".json"), b, 0o600)
}

// LoadRecord reads a saved apply record.
func LoadRecord(stateDir, id string) (*Record, error) {
	if !strings.HasPrefix(id, "x-") || strings.ContainsAny(id, `/\.`) {
		return nil, fmt.Errorf("invalid apply id %q", id)
	}
	b, err := os.ReadFile(filepath.Join(stateDir, "applies", id+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no apply with id %s (ids are printed after each apply and in `vio log`)", id)
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if err := r.Plan.CheckIntegrity(); err != nil {
		return nil, err
	}
	return &r, nil
}

// Rollback reverts the applied actions of a past apply, newest first.
func Rollback(ctx context.Context, e *Env, r *Record) ([]plan.Outcome, error) {
	var outs []plan.Outcome
	var errs []error
	for i := len(r.Outcomes) - 1; i >= 0; i-- {
		o := r.Outcomes[i]
		if o.Status != "applied" {
			continue
		}
		var a *plan.Action
		for j := range r.Plan.Actions {
			if r.Plan.Actions[j].ID == o.ActionID {
				a = &r.Plan.Actions[j]
			}
		}
		if a == nil {
			continue
		}
		e.emit(a, "rollback", "rolling back %s", a.Summary)
		if err := e.rollbackOne(ctx, r.ID, a); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", a.ID, err))
			outs = append(outs, plan.Outcome{ActionID: a.ID, Status: "rollback_failed", Message: err.Error()})
			continue
		}
		if a.Has(plan.RiskLockout) {
			h, _ := e.Host(ctx, a.Host)
			if err := e.probe(ctx, h, a.Host, plan.Probe{Kind: plan.ProbeSSHLogin}); err != nil {
				errs = append(errs, fmt.Errorf("%s: rolled back, but a fresh login failed: %w", a.ID, err))
			}
		}
		e.emit(a, "reverted", "rolled back")
		outs = append(outs, plan.Outcome{ActionID: a.ID, Status: "rolled_back"})
	}
	return outs, errors.Join(errs...)
}

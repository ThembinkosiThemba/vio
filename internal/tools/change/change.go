// Package change holds vio's typed change tools. Each Plan is a dry run that
// reads the host and returns a plan.Action listing the exact steps, the
// rollback, preconditions and verify probes. Apply and Rollback come from
// tools.Steps, so they can only run what the approved action lists.
package change

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/tools"
)

// All returns every change and dangerous tool.
func All() []tools.Tool {
	return []tools.Tool{
		fsWrite, fsPatch,
		pkgInstall, pkgUpgrade,
		svcControl, sshdSet,
		fwRule("fw_allow", "allow"), fwRule("fw_deny", "deny"), fwEnable,
		userAdd, userLock, keyAdd, keyRemove,
		autoupdatesEnable, fail2banConfigure, timerAdd,
		// dangerous
		shellExec, fsRemove, pkgRemove, userRemove, fwDefaultDeny, hostReboot,
	}
}

// tool is the common shape of a change tool.
type tool struct {
	tools.Steps
	name, desc, schema string
	tier               plan.Tier
	plan               func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error)
}

func (t tool) Name() string            { return t.name }
func (t tool) Description() string     { return t.desc }
func (t tool) Schema() json.RawMessage { return json.RawMessage(t.schema) }
func (t tool) Tier() plan.Tier         { return t.tier }

// Plan runs the dry run and stamps the action with tool identity.
func (t tool) Plan(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
	if !h.Facts.Root && !h.Facts.Sudo {
		return plan.Action{}, fmt.Errorf("%s: changes need root or passwordless sudo, and %s has neither for user %s", t.name, h.Name, h.Facts.User)
	}
	a, err := t.plan(ctx, h, raw)
	if err != nil {
		return plan.Action{}, fmt.Errorf("%s: %w", t.name, err)
	}
	a.Host, a.Tool, a.Tier = h.Name, t.name, t.tier
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	a.Args = raw
	if err := a.Validate(); err != nil {
		return plan.Action{}, err
	}
	return a, nil
}

func meta(a *plan.Action, k, v string) {
	if a.Meta == nil {
		a.Meta = map[string]string{}
	}
	a.Meta[k] = v
}

func rollback(a *plan.Action) *plan.RollbackSpec {
	if a.Rollback == nil {
		a.Rollback = &plan.RollbackSpec{}
	}
	return a.Rollback
}

// fileEdit captures a file's state at plan time so the action can rewrite it,
// check it hasn't drifted, and restore it.
type fileEdit struct {
	path   string
	before []byte
	exists bool
	mode   string // e.g. "0644"
	owner  string // user:group
}

func readForEdit(ctx context.Context, h *tools.Host, path string) (fileEdit, error) {
	e := fileEdit{path: path}
	data, exists, err := h.ReadFile(ctx, path)
	if err != nil {
		return e, err
	}
	e.before, e.exists = data, exists
	if exists {
		out, err := h.Output(ctx, "stat", "-c", "%a %U:%G", "--", path)
		if err != nil {
			return e, err
		}
		if f := strings.Fields(out); len(f) == 2 {
			e.mode, e.owner = strings.Repeat("0", max(0, 4-len(f[0])))+f[0], f[1]
		}
	}
	return e, nil
}

// write adds the write step, diff, precondition and file restore to a.
// mode and owner apply only to new files; existing files keep theirs.
func (e fileEdit) write(a *plan.Action, content, mode, owner string) {
	if e.exists {
		mode, owner = e.mode, e.owner
	}
	if d := plan.Diff(e.path, string(e.before), content); d != "" {
		a.Diff += d
	}
	a.Steps = append(a.Steps, plan.Step{Kind: "write", Desc: "write " + e.path, Path: e.path, Content: content, Mode: mode, Owner: owner})
	a.Preconditions = append(a.Preconditions, plan.FileState(e.path, e.before, e.exists))
	rb := rollback(a)
	rb.Restore = append(rb.Restore, e.path)
}

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._+:-]{0,127}$`)
	userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

func checkName(kind, s string) error {
	if !nameRE.MatchString(s) {
		return fmt.Errorf("invalid %s name %q", kind, s)
	}
	return nil
}

func checkPath(p string) error {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\n\r") || strings.Contains("/"+p+"/", "/../") {
		return fmt.Errorf("path must be absolute and normalized, got %q", p)
	}
	return nil
}

// stateProbe checks a service is active after apply.
func stateProbe(desc string, argv []string, want string) plan.Probe {
	return plan.Probe{Kind: plan.ProbeCmd, Desc: desc, Args: argv, Want: want}
}

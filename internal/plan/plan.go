// Package plan is the data model for changes: a Plan of typed Actions, each
// carrying the exact steps it will run, its rollback, preconditions, verify
// probes and risk flags. Approval binds to the plan's hash, so what runs is
// exactly what was approved. See specs/plan.md §5.8.
package plan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ThembinkosiThemba/vio/internal/fsutil"
)

// Tier orders tools by how much they can change.
type Tier int

const (
	Observe Tier = iota
	Change
	Dangerous
)

func (t Tier) String() string {
	switch t {
	case Observe:
		return "observe"
	case Change:
		return "change"
	case Dangerous:
		return "dangerous"
	}
	return fmt.Sprintf("tier(%d)", int(t))
}

// ParseTier parses "observe", "change" or "dangerous".
func ParseTier(s string) (Tier, error) {
	switch s {
	case "observe":
		return Observe, nil
	case "change":
		return Change, nil
	case "dangerous":
		return Dangerous, nil
	}
	return 0, fmt.Errorf("unknown tier %q (want observe, change or dangerous)", s)
}

func (t Tier) MarshalJSON() ([]byte, error) { return json.Marshal(t.String()) }

func (t *Tier) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseTier(s)
	*t = v
	return err
}

// Risk flags an action's possible consequences.
type Risk string

const (
	RiskLockout      Risk = "lockout"      // may cut off the operator's access
	RiskDowntime     Risk = "downtime"     // may interrupt a service
	RiskDataLoss     Risk = "data_loss"    // may destroy data
	RiskIrreversible Risk = "irreversible" // cannot be rolled back
)

// Step is one unit of work on the host. Steps run as root, in order.
type Step struct {
	Kind    string   `json:"kind"`              // "run" or "write"
	Desc    string   `json:"desc,omitempty"`    // human description
	Args    []string `json:"args,omitempty"`    // run: argv
	Path    string   `json:"path,omitempty"`    // write: absolute path
	Content string   `json:"content,omitempty"` // write: file content; secret://NAME refs resolve at apply time
	Mode    string   `json:"mode,omitempty"`    // write: octal, e.g. "0644"
	Owner   string   `json:"owner,omitempty"`   // write: user[:group], optional
}

// Run returns a run step.
func Run(desc string, args ...string) Step { return Step{Kind: "run", Desc: desc, Args: args} }

// Write returns a write step.
func Write(path, content, mode string) Step {
	return Step{Kind: "write", Desc: "write " + path, Path: path, Content: content, Mode: mode}
}

// Precondition must hold when the action is applied, or the plan has drifted.
// Args run as root; their trimmed stdout must equal Want.
type Precondition struct {
	Desc string   `json:"desc"`
	Args []string `json:"args"`
	Want string   `json:"want"`
}

// fileHashScript prints a file's sha256, or "absent".
const fileHashScript = `if [ -e "$1" ]; then sha256sum -- "$1" | cut -d' ' -f1; else echo absent; fi`

// FileState is a precondition that path still has the content it had at plan time.
func FileState(path string, content []byte, exists bool) Precondition {
	want := "absent"
	if exists {
		sum := sha256.Sum256(content)
		want = hex.EncodeToString(sum[:])
	}
	return Precondition{Desc: path + " unchanged since planning", Args: []string{"sh", "-c", fileHashScript, "sh", path}, Want: want}
}

// RollbackSpec undoes an action: restore backed-up files, then run commands.
type RollbackSpec struct {
	Restore  []string   `json:"restore,omitempty"`
	Commands [][]string `json:"commands,omitempty"`
}

// Empty reports whether the rollback does nothing.
func (r *RollbackSpec) Empty() bool { return r == nil || len(r.Restore) == 0 && len(r.Commands) == 0 }

// Probe kinds.
const (
	ProbeCmd      = "cmd"       // Args exit 0 (and stdout contains Want, if set)
	ProbeSSHLogin = "ssh_login" // a brand-new SSH connection can log in and run `true`
)

// Probe is a post-apply check.
type Probe struct {
	Kind string   `json:"kind"`
	Desc string   `json:"desc"`
	Args []string `json:"args,omitempty"`
	Want string   `json:"want,omitempty"`
}

// TaintSource records an argument that came from host data rather than the operator.
type TaintSource struct {
	Arg    string `json:"arg"`
	Value  string `json:"value"`
	Source string `json:"source"`
}

// Action is one proposed change on one host.
type Action struct {
	ID            string            `json:"id"`
	Host          string            `json:"host"`
	Tool          string            `json:"tool"`
	Args          json.RawMessage   `json:"args"`
	Tier          Tier              `json:"tier"`
	Summary       string            `json:"summary"`
	Diff          string            `json:"diff,omitempty"`
	Risk          []Risk            `json:"risk,omitempty"`
	Meta          map[string]string `json:"meta,omitempty"` // structured facts for policy rules
	Steps         []Step            `json:"steps"`
	Preconditions []Precondition    `json:"preconditions,omitempty"`
	Rollback      *RollbackSpec     `json:"rollback,omitempty"`
	Verify        []Probe           `json:"verify,omitempty"`
	Taint         []TaintSource     `json:"taint,omitempty"`
	DependsOn     []string          `json:"depends_on,omitempty"`
}

// Has reports whether the action carries risk r.
func (a *Action) Has(r Risk) bool { return slices.Contains(a.Risk, r) }

// AddRisk adds r once.
func (a *Action) AddRisk(r Risk) {
	if !a.Has(r) {
		a.Risk = append(a.Risk, r)
	}
}

// Validate checks the invariants every action must satisfy.
func (a *Action) Validate() error {
	if a.Host == "" || a.Tool == "" {
		return errors.New("action needs a host and a tool")
	}
	if len(a.Steps) == 0 {
		return fmt.Errorf("%s: nothing to do", a.Tool)
	}
	for _, s := range a.Steps {
		switch s.Kind {
		case "run":
			if len(s.Args) == 0 {
				return fmt.Errorf("%s: empty command", a.Tool)
			}
		case "write":
			if !strings.HasPrefix(s.Path, "/") {
				return fmt.Errorf("%s: write path must be absolute", a.Tool)
			}
		default:
			return fmt.Errorf("%s: unknown step kind %q", a.Tool, s.Kind)
		}
	}
	// Invariant 2: no rollback only if explicitly irreversible.
	if a.Rollback.Empty() && !a.Has(RiskIrreversible) {
		return fmt.Errorf("%s: has no rollback and is not marked irreversible", a.Tool)
	}
	return nil
}

// Approval binds an operator's yes to one plan hash.
type Approval struct {
	PlanHash string    `json:"plan_hash"`
	Operator string    `json:"operator"`
	At       time.Time `json:"at"`
	MaxTier  Tier      `json:"max_tier"`
}

// Plan is a set of actions approved and applied together.
type Plan struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Goal      string    `json:"goal"`
	Hosts     []string  `json:"hosts"`
	Actions   []Action  `json:"actions"`
	Hash      string    `json:"hash"`
	Approval  *Approval `json:"approval,omitempty"`
}

// New builds and seals a plan.
func New(goal string, actions []Action) (*Plan, error) {
	p := &Plan{CreatedAt: time.Now().UTC().Truncate(time.Second), Goal: goal, Actions: actions}
	for i := range p.Actions {
		a := &p.Actions[i]
		a.ID = fmt.Sprintf("a%d", i+1)
		if err := a.Validate(); err != nil {
			return nil, err
		}
		if !slices.Contains(p.Hosts, a.Host) {
			p.Hosts = append(p.Hosts, a.Host)
		}
	}
	if err := p.Seal(); err != nil {
		return nil, err
	}
	return p, nil
}

// ComputeHash returns the sha256 of the plan's canonical JSON, excluding ID,
// Hash and Approval.
func (p *Plan) ComputeHash() (string, error) {
	c := *p
	c.ID, c.Hash, c.Approval = "", "", nil
	c.Actions = slices.Clone(p.Actions)
	for i := range c.Actions {
		if len(c.Actions[i].Args) > 0 {
			var buf bytes.Buffer
			if err := json.Compact(&buf, c.Actions[i].Args); err != nil {
				return "", fmt.Errorf("plan: action %s args: %w", c.Actions[i].ID, err)
			}
			c.Actions[i].Args = buf.Bytes()
		}
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Seal sets Hash and ID from the current contents.
func (p *Plan) Seal() error {
	h, err := p.ComputeHash()
	if err != nil {
		return err
	}
	p.Hash, p.ID = h, "p-"+h[:6]
	return nil
}

// ErrTampered means a plan's contents no longer match its hash or approval.
var ErrTampered = errors.New("plan contents do not match its hash")

// CheckIntegrity recomputes the hash and, if approved, checks the approval binds to it.
func (p *Plan) CheckIntegrity() error {
	h, err := p.ComputeHash()
	if err != nil {
		return err
	}
	if h != p.Hash {
		return ErrTampered
	}
	if p.Approval != nil && p.Approval.PlanHash != h {
		return fmt.Errorf("%w: approval is for a different plan", ErrTampered)
	}
	return nil
}

// Approve records the operator's approval of the current hash.
func (p *Plan) Approve(operator string, max Tier) error {
	if err := p.CheckIntegrity(); err != nil {
		return err
	}
	p.Approval = &Approval{PlanHash: p.Hash, Operator: operator, At: time.Now().UTC(), MaxTier: max}
	return nil
}

// MaxTier is the highest tier among the actions.
func (p *Plan) MaxTier() Tier {
	t := Observe
	for _, a := range p.Actions {
		t = max(t, a.Tier)
	}
	return t
}

// Risks lists the distinct risks across actions.
func (p *Plan) Risks() []Risk {
	var out []Risk
	for _, a := range p.Actions {
		for _, r := range a.Risk {
			if !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	return out
}

// Save writes the plan as indented JSON with owner-only permissions.
func (p *Plan) Save(path string) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, append(b, '\n'), 0o600)
}

// Load reads a plan file and checks its integrity.
func Load(path string) (*Plan, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := p.CheckIntegrity(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

// Outcome is what happened to one action.
type Outcome struct {
	ActionID string `json:"action_id"`
	Status   string `json:"status"` // applied | failed | rolled_back | reverted | skipped
	Message  string `json:"message,omitempty"`
}

// Package tools defines vio's tool model: tiers, the observe and change tool
// interfaces, and the registry the agent exposes to the model.
//
// Observe tools only read. Change tools never touch the host from Plan; they
// return a plan.Action describing the exact steps, and Apply runs only those
// steps. See specs/plan.md §5.7.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ThembinkosiThemba/vio/internal/facts"
	"github.com/ThembinkosiThemba/vio/internal/llm"
	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

// Host is a connected target as tools see it.
type Host struct {
	Name  string
	Tags  []string
	X     transport.Executor // runs as the login user
	Facts facts.Facts
}

// Root returns an executor that runs as root: the login user if it is root,
// otherwise via `sudo -n`.
func (h *Host) Root() transport.Executor {
	if h.Facts.Root {
		return h.X
	}
	return transport.Elevated(h.X)
}

// Run runs argv, as root when sudo is set.
func (h *Host) Run(ctx context.Context, sudo bool, args ...string) (transport.Result, error) {
	x := h.X
	if sudo {
		x = h.Root()
	}
	return x.Run(ctx, transport.Cmd{Args: args})
}

// Output reads argv's stdout as root, failing on a non-zero exit.
func (h *Host) Output(ctx context.Context, args ...string) (string, error) {
	res, err := h.Run(ctx, true, args...)
	if err != nil {
		return "", err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = fmt.Sprintf("exit %d", res.ExitCode)
		}
		return "", fmt.Errorf("%s: %s", args[0], msg)
	}
	return string(res.Stdout), nil
}

// MaxEditSize bounds files that change tools read and rewrite.
const MaxEditSize = 4 << 20

// ReadFile reads a whole file as root. A missing file returns exists=false and
// no error. Files over MaxEditSize are an error, never silently truncated,
// because callers write the content back.
func (h *Host) ReadFile(ctx context.Context, p string) (data []byte, exists bool, err error) {
	data, info, err := h.Root().ReadFile(ctx, p, MaxEditSize+1)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Size > MaxEditSize || len(data) > MaxEditSize {
		return nil, true, fmt.Errorf("%s is larger than %d MiB; vio won't rewrite it", p, MaxEditSize>>20)
	}
	return data, true, nil
}

// Tool is anything the model can call.
type Tool interface {
	Name() string
	Description() string
	Schema() json.RawMessage
	Tier() plan.Tier
}

// Output is an observe tool's result, before redaction.
type Output struct {
	Label     string // what ran, for display and audit, e.g. "ss -tlnp"
	Text      string
	Exit      int
	Truncated bool
}

// ObserveTool reads host state. It must never change it.
type ObserveTool interface {
	Tool
	Observe(ctx context.Context, h *Host, args json.RawMessage) (Output, error)
}

// ChangeTool proposes and performs a change.
type ChangeTool interface {
	Tool
	// Plan is a dry run: it may read the host, and must not change it.
	Plan(ctx context.Context, h *Host, args json.RawMessage) (plan.Action, error)
	// Apply runs the action's steps.
	Apply(ctx context.Context, h *Host, a plan.Action) (plan.Outcome, error)
	// Rollback runs the action's rollback commands. Restoring backed-up files
	// is the apply engine's job and happens first.
	Rollback(ctx context.Context, h *Host, a plan.Action) error
}

// Registry holds tools in registration order.
type Registry struct {
	byName map[string]Tool
	order  []string
}

// NewRegistry returns a registry holding ts.
func NewRegistry(ts ...Tool) *Registry {
	r := &Registry{byName: map[string]Tool{}}
	for _, t := range ts {
		r.Add(t)
	}
	return r
}

// Add registers t. A duplicate name panics: it is a programming error.
func (r *Registry) Add(t Tool) {
	if _, dup := r.byName[t.Name()]; dup {
		panic("tools: duplicate tool " + t.Name())
	}
	r.byName[t.Name()] = t
	r.order = append(r.order, t.Name())
}

// Get returns the named tool.
func (r *Registry) Get(name string) (Tool, bool) {
	t, ok := r.byName[name]
	return t, ok
}

// List returns tools up to tier max, in registration order.
func (r *Registry) List(max plan.Tier) []Tool {
	var out []Tool
	for _, n := range r.order {
		if t := r.byName[n]; t.Tier() <= max {
			out = append(out, t)
		}
	}
	return out
}

// Specs returns model-facing specs for tools up to max. Each schema gains a
// "host" property, since every tool runs on one inventory host.
func (r *Registry) Specs(max plan.Tier) []llm.Tool {
	var out []llm.Tool
	for _, t := range r.List(max) {
		desc := t.Description()
		if t.Tier() >= plan.Change {
			desc = "[" + t.Tier().String() + ": proposes a change for operator approval; nothing runs until approved] " + desc
		}
		out = append(out, llm.Tool{Name: t.Name(), Description: desc, Schema: WithHost(t.Schema())})
	}
	return out
}

// WithHost adds an optional "host" string property to a JSON object schema.
func WithHost(schema json.RawMessage) json.RawMessage {
	var s map[string]any
	if json.Unmarshal(schema, &s) != nil {
		return schema
	}
	props, _ := s["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
	}
	props["host"] = map[string]any{"type": "string", "description": "Inventory name of the server. Optional when there is only one."}
	s["properties"] = props
	b, err := json.Marshal(s)
	if err != nil {
		return schema
	}
	return b
}

// Decode unmarshals tool arguments, ignoring the "host" key.
func Decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

// Steps is embedded by change tools: Apply runs exactly the approved steps,
// and Rollback runs exactly the approved rollback commands.
type Steps struct{}

// Apply runs a's steps as root, stopping at the first failure.
func (Steps) Apply(ctx context.Context, h *Host, a plan.Action) (plan.Outcome, error) {
	if err := RunSteps(ctx, h.Root(), a.Steps); err != nil {
		return plan.Outcome{ActionID: a.ID, Status: "failed", Message: err.Error()}, err
	}
	return plan.Outcome{ActionID: a.ID, Status: "applied"}, nil
}

// Rollback runs a's rollback commands as root. It keeps going past failures
// so as much as possible is undone, and reports them all.
func (Steps) Rollback(ctx context.Context, h *Host, a plan.Action) error {
	if a.Rollback == nil {
		return nil
	}
	var errs []error
	for _, c := range a.Rollback.Commands {
		if err := runChecked(ctx, h.Root(), c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// StepTimeout bounds one step; package operations can be slow.
const StepTimeout = 15 * time.Minute

// RunSteps executes steps in order on x (which should run as root).
func RunSteps(ctx context.Context, x transport.Executor, steps []plan.Step) error {
	for i, s := range steps {
		var err error
		switch s.Kind {
		case "run":
			err = runChecked(ctx, x, s.Args)
		case "write":
			err = writeStep(ctx, x, s)
		default:
			err = fmt.Errorf("unknown step kind %q", s.Kind)
		}
		if err != nil {
			return fmt.Errorf("step %d (%s): %w", i+1, s.Desc, err)
		}
	}
	return nil
}

func runChecked(ctx context.Context, x transport.Executor, args []string) error {
	res, err := x.Run(ctx, transport.Cmd{Args: args, Timeout: StepTimeout})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if msg == "" {
			msg = strings.TrimSpace(string(res.Stdout))
		}
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
		}
		return fmt.Errorf("%s exited %d: %s", args[0], res.ExitCode, msg)
	}
	return nil
}

func writeStep(ctx context.Context, x transport.Executor, s plan.Step) error {
	content, err := ResolveSecrets(s.Content)
	if err != nil {
		return err
	}
	mode := fs.FileMode(0o644)
	if s.Mode != "" {
		m, err := strconv.ParseUint(s.Mode, 8, 32)
		if err != nil {
			return fmt.Errorf("bad mode %q", s.Mode)
		}
		mode = fs.FileMode(m)
	}
	if err := runChecked(ctx, x, []string{"mkdir", "-p", "--", path.Dir(s.Path)}); err != nil {
		return err
	}
	if err := x.WriteFile(ctx, s.Path, []byte(content), mode); err != nil {
		return err
	}
	if s.Owner != "" {
		return runChecked(ctx, x, []string{"chown", "--", s.Owner, s.Path})
	}
	return nil
}

var secretRef = regexp.MustCompile(`secret://([A-Za-z0-9_]+)`)

// ResolveSecrets replaces secret://NAME with $VIO_SECRET_NAME from the operator's
// environment. The model only ever sees the reference.
func ResolveSecrets(s string) (string, error) {
	var missing []string
	out := secretRef.ReplaceAllStringFunc(s, func(m string) string {
		name := strings.ToUpper(secretRef.FindStringSubmatch(m)[1])
		v, ok := os.LookupEnv("VIO_SECRET_" + name)
		if !ok {
			missing = append(missing, "VIO_SECRET_"+name)
		}
		return v
	})
	if len(missing) > 0 {
		slices.Sort(missing)
		return "", fmt.Errorf("secret not set in the environment: %s", strings.Join(slices.Compact(missing), ", "))
	}
	return out, nil
}

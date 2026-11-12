// Package agent runs vio's conversation loop. The model reasons with observe
// tools; change tools only produce proposed plan actions. When the model ends
// its turn, proposals become one plan that goes through policy and operator
// approval, and the deterministic apply engine runs it. The model is never in
// the execution loop. See specs/plan.md §5.2.
package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ThembinkosiThemba/vio/internal/apply"
	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/checks"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/llm"
	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/policy"
	"github.com/ThembinkosiThemba/vio/internal/redact"
	"github.com/ThembinkosiThemba/vio/internal/runbooks"
	"github.com/ThembinkosiThemba/vio/internal/tools"
	"github.com/ThembinkosiThemba/vio/internal/tools/change"
	"github.com/ThembinkosiThemba/vio/internal/tools/observe"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

// UI is how the session talks to the operator.
type UI interface {
	// Text receives model output as it streams.
	Text(s string)
	// ToolStart announces a tool call, e.g. ("web-1", "df -h").
	ToolStart(host, label string)
	// ToolDone reports the outcome of the last ToolStart.
	ToolDone(err error)
	// Confirm asks the operator a yes/no question. Non-interactive UIs answer no.
	Confirm(question string) bool
	// Notice shows a status line from vio itself (not the model).
	Notice(s string)
	// ReviewPlan shows a plan with its policy verdicts and asks for approval.
	// It is only called when no action is denied. Non-interactive UIs answer no.
	ReviewPlan(p *plan.Plan, verdicts map[string]policy.Result) bool
	// Progress reports apply engine progress.
	Progress(e apply.Event)
}

// Env connects the session to the rest of vio. Keeping these as functions lets
// the CLI own prompts, inventory files, and host-key trust.
type Env struct {
	Inventory func() (*inventory.Inventory, error)
	AddHost   func(h inventory.Host) error
	Trust     func(ctx context.Context, name string) error
	// Dial opens a new connection each call; the session caches one per host.
	Dial   func(ctx context.Context, h *inventory.Host) (transport.Executor, error)
	Record func(audit.Record) error
}

// Mode says what happens to proposed changes.
type Mode int

const (
	// ModeApply reviews proposals with the operator and applies approved plans.
	ModeApply Mode = iota
	// ModeCollect keeps proposals for TakePlan (used by `vio plan`).
	ModeCollect
)

// Options tune a session.
type Options struct {
	MaxSteps    int       // model calls per operator message
	MaxOutput   int       // bytes of one tool result shown to the model
	MaxTier     plan.Tier // highest tool tier offered to the model
	Mode        Mode
	Policy      *policy.Engine // nil means built-in rules only
	GuardWindow time.Duration
	StateDir    string // apply records, for `vio rollback`
	Operator    string // recorded in approvals
	Runbooks    []runbooks.Runbook
	// ContextBudget is the total bytes of tool output kept verbatim in the
	// conversation; older results beyond it are compacted to a reference.
	ContextBudget int
}

// Session is one conversation.
type Session struct {
	model   llm.Provider
	env     Env
	ui      UI
	opts    Options
	reg     *tools.Registry
	system  string
	history []llm.Message
	hosts   map[string]*tools.Host
	usage   llm.Usage

	proposed []plan.Action
	goal     string
	spool    map[string]string // ref → full redacted output
	hostData strings.Builder   // everything read from hosts, for taint checks
	trusted  strings.Builder   // operator messages and inventory notes
}

// Registry returns every tool vio has.
func Registry() *tools.Registry {
	r := tools.NewRegistry(observe.All()...)
	r.Add(checks.Tool{})
	for _, t := range change.All() {
		r.Add(t)
	}
	return r
}

// New starts a session. model may be nil; Send then returns ErrNoModel until
// SetModel is called.
func New(model llm.Provider, env Env, ui UI, opts Options) (*Session, error) {
	if opts.MaxSteps <= 0 {
		opts.MaxSteps = 40
	}
	if opts.MaxOutput <= 0 {
		opts.MaxOutput = 16 * 1024
	}
	if opts.Policy == nil {
		opts.Policy = policy.New()
	}
	if opts.GuardWindow <= 0 {
		opts.GuardWindow = 120 * time.Second
	}
	if opts.ContextBudget <= 0 {
		opts.ContextBudget = 256 * 1024
	}
	s := &Session{model: model, env: env, ui: ui, opts: opts, reg: Registry(),
		hosts: map[string]*tools.Host{}, spool: map[string]string{}}
	if err := s.refreshSystem(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Session) refreshSystem() error {
	inv, err := s.env.Inventory()
	if err != nil {
		return err
	}
	s.system = systemPrompt(inv, s.opts)
	for _, h := range inv.All() {
		s.trusted.WriteString(h.Notes + "\n" + h.Name + "\n" + h.User + "\n")
	}
	return nil
}

// Usage returns tokens used so far.
func (s *Session) Usage() llm.Usage { return s.usage }

// Model returns the provider in use, or nil if none is configured.
func (s *Session) Model() llm.Provider { return s.model }

// SetModel switches the provider. The conversation is kept; adapters ignore
// provider-specific data they don't recognise.
func (s *Session) SetModel(p llm.Provider) { s.model = p }

// MaxTier is the highest tool tier this session offers.
func (s *Session) MaxTier() plan.Tier { return s.opts.MaxTier }

// ErrNoModel means the session has no model provider yet.
var ErrNoModel = errors.New("no model configured")

// Refresh re-reads the inventory into the system prompt, keeping the conversation.
func (s *Session) Refresh() error { return s.refreshSystem() }

// Reset forgets the conversation and pending proposals (connections are kept).
func (s *Session) Reset() error {
	s.history, s.proposed = nil, nil
	s.spool = map[string]string{}
	s.hostData.Reset()
	s.trusted.Reset()
	return s.refreshSystem()
}

// Close drops all host connections.
func (s *Session) Close() {
	for name, h := range s.hosts {
		h.X.Close()
		delete(s.hosts, name)
	}
}

// ErrStepLimit means the model kept calling tools past Options.MaxSteps.
var ErrStepLimit = errors.New("step limit reached")

// maxPlanRounds bounds review → apply → explain cycles in one Send.
const maxPlanRounds = 3

// Send handles one operator message: it loops model ⇄ tools until the model
// answers. On failure the conversation is rolled back to before the message, so
// the history never holds a tool call without its result.
func (s *Session) Send(ctx context.Context, text string) error {
	if s.model == nil {
		return ErrNoModel
	}
	start := len(s.history)
	s.history = append(s.history, llm.Message{Role: llm.RoleUser, Text: text})
	s.trusted.WriteString(text + "\n")
	s.goal = text
	seen := map[string]int{}
	rounds := 0

	for step := 0; step < s.opts.MaxSteps; step++ {
		s.compact()
		resp, err := s.model.Chat(ctx, llm.Request{System: s.system, Messages: s.history, Tools: s.specs()}, s.ui.Text)
		if err != nil {
			s.history = s.history[:start]
			s.proposed = nil
			return err
		}
		s.usage.InputTokens += resp.Usage.InputTokens
		s.usage.OutputTokens += resp.Usage.OutputTokens
		s.history = append(s.history, resp.Message)

		switch resp.StopReason {
		case llm.StopRefusal:
			s.ui.Notice("The model declined to answer that.")
			s.proposed = nil
			return nil
		case llm.StopMaxTokens:
			s.ui.Notice("The model hit its output limit; its answer may be cut off.")
		}
		if len(resp.Message.ToolCalls) == 0 {
			if len(s.proposed) == 0 || s.opts.Mode == ModeCollect || rounds >= maxPlanRounds {
				return nil
			}
			rounds++
			note, err := s.resolvePlan(ctx)
			if err != nil {
				return err
			}
			// Tell the model what happened so it can explain the result.
			s.history = append(s.history, llm.Message{Role: llm.RoleUser, Text: note})
			continue
		}

		results := make([]llm.ToolResult, 0, len(resp.Message.ToolCalls))
		for _, call := range resp.Message.ToolCalls {
			key := call.Name + string(call.Args)
			seen[key]++
			var out string
			var isErr bool
			switch {
			case ctx.Err() != nil:
				out, isErr = "cancelled by the operator", true
			case seen[key] > 2:
				out, isErr = "You already ran this exact call twice. Use the earlier output, or try something different.", true
			default:
				out, isErr = s.runTool(ctx, call)
			}
			results = append(results, llm.ToolResult{CallID: call.ID, Content: out, IsError: isErr})
		}
		s.history = append(s.history, llm.Message{Role: llm.RoleUser, ToolResults: results})
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	s.ui.Notice(fmt.Sprintf("Stopped after %d steps. Ask me to continue if you want me to keep going.", s.opts.MaxSteps))
	return ErrStepLimit
}

// Pending returns the proposals not yet turned into a plan.
func (s *Session) Pending() []plan.Action { return s.proposed }

// TakePlan seals the pending proposals into a plan and clears them.
func (s *Session) TakePlan(goal string) (*plan.Plan, error) {
	if len(s.proposed) == 0 {
		return nil, errors.New("no changes were proposed")
	}
	if goal == "" {
		goal = s.goal
	}
	p, err := plan.New(goal, s.proposed)
	s.proposed = nil
	return p, err
}

// PolicyContext returns the policy context for this session's hosts.
func (s *Session) PolicyContext() policy.Context {
	pc := policy.Context{MaxTier: s.opts.MaxTier, AuthMethod: "publickey", HostTags: map[string][]string{}}
	if inv, err := s.env.Inventory(); err == nil {
		for _, h := range inv.All() {
			pc.HostTags[h.Name] = h.Tags
		}
	}
	return pc
}

// resolvePlan turns proposals into a plan, reviews it with the operator, and
// applies it if approved. It returns a note for the model.
func (s *Session) resolvePlan(ctx context.Context) (string, error) {
	p, err := s.TakePlan("")
	if err != nil {
		return "[vio] The proposed changes could not form a plan: " + err.Error(), nil
	}
	worst, verdicts := s.opts.Policy.EvaluatePlan(s.PolicyContext(), p)
	if err := s.recordPlan(p, worst, verdicts); err != nil {
		return "", err
	}
	if worst == policy.Deny {
		s.ui.ReviewPlan(p, verdicts) // shows the denial; approval is not possible
		var why []string
		for _, a := range p.Actions {
			for _, r := range verdicts[a.ID].Reasons {
				if r.Decision == policy.Deny {
					why = append(why, a.ID+" ("+a.Summary+"): "+r.Msg)
				}
			}
		}
		return fmt.Sprintf("[vio] Policy denied plan %s, so nothing was changed and the operator was not asked. Reasons: %s. "+
			"Explain this to the operator; propose a safer alternative only if one exists.", p.ID, strings.Join(why, "; ")), nil
	}
	if !s.ui.ReviewPlan(p, verdicts) {
		_ = s.record(audit.Record{Kind: audit.KindApprove, Tool: "plan", Msg: p.ID + " declined"})
		return fmt.Sprintf("[vio] The operator declined plan %s. Nothing was changed. Acknowledge briefly; don't propose it again unless asked.", p.ID), nil
	}
	if err := p.Approve(s.opts.Operator, s.opts.MaxTier); err != nil {
		return "", err
	}
	if err := s.record(audit.Record{Kind: audit.KindApprove, Tool: "plan", Msg: p.ID + " approved, hash " + p.Hash}); err != nil {
		return "", fmt.Errorf("audit log unavailable, stopping: %w", err)
	}
	rep, err := apply.Apply(ctx, s.applyEnv(), p)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[vio] The operator approved plan %s and vio applied it (apply id %s). Results:\n", p.ID, rep.ID)
	for _, o := range rep.Outcomes {
		fmt.Fprintf(&b, "- %s: %s", o.ActionID, o.Status)
		if o.Message != "" {
			b.WriteString(" — " + o.Message)
		}
		b.WriteByte('\n')
	}
	b.WriteString("Summarize the outcome for the operator in a few lines. If something was rolled back, say why. " +
		"They can undo applied changes later with `vio rollback " + rep.ID + "`.")
	// Facts like firewall state may have changed.
	for name := range s.hosts {
		s.refreshFacts(ctx, name)
	}
	return b.String(), nil
}

// ApplyEnv builds the apply engine environment for this session.
func (s *Session) applyEnv() *apply.Env {
	return &apply.Env{
		Host: s.hostByName,
		Fresh: func(ctx context.Context, name string) (transport.Executor, error) {
			ih, err := s.resolveHost(name)
			if err != nil {
				return nil, err
			}
			return s.env.Dial(ctx, ih)
		},
		Tools:       s.reg,
		Policy:      s.opts.Policy,
		PolicyCtx:   s.PolicyContext(),
		Record:      s.env.Record,
		Progress:    s.ui.Progress,
		GuardWindow: s.opts.GuardWindow,
		StateDir:    s.opts.StateDir,
	}
}

// ApplyEnv exposes the engine environment to CLI commands (apply, rollback, check --fix).
func (s *Session) ApplyEnv() *apply.Env { return s.applyEnv() }

func (s *Session) recordPlan(p *plan.Plan, worst policy.Decision, verdicts map[string]policy.Result) error {
	if s.env.Record == nil {
		return nil
	}
	for _, a := range p.Actions {
		if err := s.env.Record(audit.Record{Kind: audit.KindPropose, Host: a.Host, Tool: a.Tool, Args: redact.JSON(a.Args), Msg: p.ID + "/" + a.ID + ": " + a.Summary}); err != nil {
			return fmt.Errorf("audit log unavailable, stopping: %w", err)
		}
	}
	var msgs []string
	for id, r := range verdicts {
		for _, reason := range r.Reasons {
			msgs = append(msgs, id+" "+reason.Verdict+" ("+reason.Rule+"): "+reason.Msg)
		}
	}
	return s.env.Record(audit.Record{Kind: audit.KindPolicy, Tool: "plan", Msg: p.ID + " " + worst.String() + "; " + strings.Join(msgs, "; ")})
}

func (s *Session) record(r audit.Record) error {
	if s.env.Record == nil {
		return nil
	}
	return s.env.Record(r)
}

// SetMode switches what happens to proposals at the end of a turn.
func (s *Session) SetMode(m Mode) { s.opts.Mode = m }

// Operator is the name recorded in approvals.
func (s *Session) Operator() string { return s.opts.Operator }

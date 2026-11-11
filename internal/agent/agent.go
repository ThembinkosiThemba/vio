// Package agent runs vio's conversation loop: the model reasons, calls read-only
// tools on the operator's servers, and answers. It never mutates a host; changes
// are the job of the plan/apply engine (specs/plan.md §5.10).
package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/llm"
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
}

// Env connects the session to the rest of vio. Keeping these as functions lets
// the CLI own prompts, inventory files, and host-key trust.
type Env struct {
	Inventory func() (*inventory.Inventory, error)
	AddHost   func(h inventory.Host) error
	Trust     func(ctx context.Context, name string) error
	Dial      func(ctx context.Context, h *inventory.Host) (transport.Executor, error)
	Record    func(audit.Record) error
}

// Options tune a session.
type Options struct {
	MaxSteps  int // model calls per operator message
	MaxOutput int // bytes of one tool result shown to the model
}

// Session is one conversation.
type Session struct {
	model   llm.Provider
	env     Env
	ui      UI
	opts    Options
	system  string
	history []llm.Message
	conns   map[string]transport.Executor
	usage   llm.Usage
}

// New starts a session.
func New(model llm.Provider, env Env, ui UI, opts Options) (*Session, error) {
	if opts.MaxSteps <= 0 {
		opts.MaxSteps = 40
	}
	if opts.MaxOutput <= 0 {
		opts.MaxOutput = 16 * 1024
	}
	s := &Session{model: model, env: env, ui: ui, opts: opts, conns: map[string]transport.Executor{}}
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
	s.system = systemPrompt(inv)
	return nil
}

// Usage returns tokens used so far.
func (s *Session) Usage() llm.Usage { return s.usage }

// Model returns the provider in use.
func (s *Session) Model() llm.Provider { return s.model }

// Reset forgets the conversation (connections are kept).
func (s *Session) Reset() error {
	s.history = nil
	return s.refreshSystem()
}

// Close drops all host connections.
func (s *Session) Close() {
	for name, c := range s.conns {
		c.Close()
		delete(s.conns, name)
	}
}

// ErrStepLimit means the model kept calling tools past Options.MaxSteps.
var ErrStepLimit = errors.New("step limit reached")

// Send handles one operator message: it loops model ⇄ tools until the model
// answers. On failure the conversation is rolled back to before the message, so
// the history never holds a tool call without its result.
func (s *Session) Send(ctx context.Context, text string) error {
	start := len(s.history)
	s.history = append(s.history, llm.Message{Role: llm.RoleUser, Text: text})
	seen := map[string]int{}

	for step := 0; step < s.opts.MaxSteps; step++ {
		resp, err := s.model.Chat(ctx, llm.Request{System: s.system, Messages: s.history, Tools: toolSpecs}, s.ui.Text)
		if err != nil {
			s.history = s.history[:start]
			return err
		}
		s.usage.InputTokens += resp.Usage.InputTokens
		s.usage.OutputTokens += resp.Usage.OutputTokens
		s.history = append(s.history, resp.Message)

		switch resp.StopReason {
		case llm.StopRefusal:
			s.ui.Notice("The model declined to answer that.")
			return nil
		case llm.StopMaxTokens:
			s.ui.Notice("The model hit its output limit; its answer may be cut off.")
		}
		if len(resp.Message.ToolCalls) == 0 {
			return nil
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

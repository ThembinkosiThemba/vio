package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
)

// Anthropic talks to the Claude API through the official SDK.
type Anthropic struct {
	cfg    Config
	client anthropic.Client
}

// NewAnthropic returns a Claude provider.
func NewAnthropic(c Config) *Anthropic {
	opts := []option.RequestOption{option.WithAPIKey(c.APIKey)}
	if c.BaseURL != "" {
		opts = append(opts, option.WithBaseURL(c.BaseURL))
	}
	return &Anthropic{cfg: c, client: anthropic.NewClient(opts...)}
}

func (a *Anthropic) Name() string  { return "anthropic" }
func (a *Anthropic) Model() string { return a.cfg.Model }

// Models that accept server-side refusal fallbacks ("default" routing).
var fallbackModels = []string{"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}

func (a *Anthropic) params(req Request) (anthropic.BetaMessageNewParams, error) {
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 64000
	}
	p := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(a.cfg.Model),
		MaxTokens: int64(maxTokens),
	}
	if req.System != "" {
		// Tools render before system, so this one breakpoint caches both.
		p.System = []anthropic.BetaTextBlockParam{{
			Text:         req.System,
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
		}}
	}
	if slices.Contains(fallbackModels, a.cfg.Model) {
		p.Betas = append(p.Betas, anthropic.AnthropicBetaServerSideFallback2026_07_01)
		p.Fallbacks = anthropic.BetaFallbacksParamOfDefault()
	}
	for _, t := range req.Tools {
		var schema struct {
			Properties map[string]any `json:"properties"`
			Required   []string       `json:"required"`
		}
		if err := json.Unmarshal(t.Schema, &schema); err != nil {
			return p, fmt.Errorf("tool %s: bad schema: %w", t.Name, err)
		}
		p.Tools = append(p.Tools, anthropic.BetaToolUnionParam{OfTool: &anthropic.BetaToolParam{
			Name:                t.Name,
			Description:         anthropic.String(t.Description),
			InputSchema:         anthropic.BetaToolInputSchemaParam{Properties: schema.Properties, Required: schema.Required},
			EagerInputStreaming: anthropic.Bool(true),
		}})
	}
	for _, m := range req.Messages {
		switch m.Role {
		case RoleAssistant:
			// Replay the native turn so reasoning blocks stay intact.
			if native, ok := m.Native.(anthropic.BetaMessageParam); ok {
				p.Messages = append(p.Messages, native)
				continue
			}
			var blocks []anthropic.BetaContentBlockParamUnion
			if m.Text != "" {
				blocks = append(blocks, anthropic.NewBetaTextBlock(m.Text))
			}
			for _, tc := range m.ToolCalls {
				blocks = append(blocks, anthropic.NewBetaToolUseBlock(tc.ID, json.RawMessage(tc.Args), tc.Name))
			}
			p.Messages = append(p.Messages, anthropic.BetaMessageParam{OfAssistant: &anthropic.BetaAssistantMessageParam{Content: blocks}})
		case RoleUser:
			var blocks []anthropic.BetaContentBlockParamUnion
			for _, tr := range m.ToolResults {
				blocks = append(blocks, anthropic.NewBetaToolResultBlock(tr.CallID, tr.Content, tr.IsError))
			}
			if m.Text != "" {
				blocks = append(blocks, anthropic.NewBetaTextBlock(m.Text))
			}
			p.Messages = append(p.Messages, anthropic.NewBetaUserMessage(blocks...))
		}
	}
	return p, nil
}

// Chat streams one Claude turn.
func (a *Anthropic) Chat(ctx context.Context, req Request, onText func(string)) (Response, error) {
	params, err := a.params(req)
	if err != nil {
		return Response{}, err
	}
	stream := a.client.Beta.Messages.NewStreaming(ctx, params)
	msg := anthropic.BetaMessage{}
	for stream.Next() {
		ev := stream.Current()
		if err := msg.Accumulate(ev); err != nil {
			return Response{}, fmt.Errorf("anthropic: %w", err)
		}
		if d, ok := ev.AsAny().(anthropic.BetaRawContentBlockDeltaEvent); ok {
			if t, ok := d.Delta.AsAny().(anthropic.BetaTextDelta); ok && onText != nil {
				onText(t.Text)
			}
		}
	}
	if err := stream.Err(); err != nil {
		return Response{}, fmt.Errorf("anthropic: %w", err)
	}

	out := Message{Role: RoleAssistant, Native: msg.ToParam()}
	for _, block := range msg.Content {
		switch b := block.AsAny().(type) {
		case anthropic.BetaTextBlock:
			out.Text += b.Text
		case anthropic.BetaToolUseBlock:
			out.ToolCalls = append(out.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Args: json.RawMessage(b.JSON.Input.Raw())})
		}
	}

	stop := StopEnd
	switch msg.StopReason {
	case anthropic.BetaStopReasonToolUse:
		stop = StopToolUse
	case anthropic.BetaStopReasonMaxTokens:
		stop = StopMaxTokens
	case anthropic.BetaStopReasonRefusal:
		stop = StopRefusal
	}
	return Response{
		Message:    out,
		StopReason: stop,
		Usage:      Usage{InputTokens: int(msg.Usage.InputTokens), OutputTokens: int(msg.Usage.OutputTokens)},
	}, nil
}

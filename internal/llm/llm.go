// Package llm is vio's provider-neutral interface to language models.
//
// The agent only speaks these types. Each adapter (OpenAI-compatible, Anthropic)
// translates them to its wire format, so no vendor is baked into the agent.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Role of a message author.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
)

// Message is one conversation turn. A user turn carries Text and/or ToolResults;
// an assistant turn carries Text and/or ToolCalls.
type Message struct {
	Role        Role
	Text        string
	ToolCalls   []ToolCall
	ToolResults []ToolResult

	// Native is the adapter's own representation of an assistant turn, replayed
	// verbatim when present (e.g. to preserve reasoning blocks). Adapters must
	// ignore values they don't recognise.
	Native any
}

// ToolCall is the model asking to run a tool.
type ToolCall struct {
	ID   string
	Name string
	Args json.RawMessage
}

// ToolResult answers one ToolCall.
type ToolResult struct {
	CallID  string
	Content string
	IsError bool
}

// Tool describes a tool the model may call. Schema is a JSON Schema object.
type Tool struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

// Request is one model call.
type Request struct {
	System    string
	Messages  []Message
	Tools     []Tool
	MaxTokens int
}

// Stop reasons, normalised across providers.
const (
	StopEnd       = "end"
	StopToolUse   = "tool_use"
	StopMaxTokens = "max_tokens"
	StopRefusal   = "refusal"
)

// Response is a finished model turn.
type Response struct {
	Message    Message // assistant turn, ready to append to history
	StopReason string
	Usage      Usage
}

// Usage counts tokens for one call.
type Usage struct {
	InputTokens  int
	OutputTokens int
}

// Provider is a model backend.
type Provider interface {
	// Name is the provider id, e.g. "ollama".
	Name() string
	// Model is the model id in use.
	Model() string
	// Chat runs one model turn, streaming text deltas to onText as they arrive.
	Chat(ctx context.Context, req Request, onText func(string)) (Response, error)
}

// Config selects and configures a provider.
type Config struct {
	Provider string // ollama | openai | openrouter | openai-compatible | anthropic
	Model    string
	BaseURL  string // optional override
	APIKey   string
}

// Known providers, in the order the setup wizard offers them.
var Providers = []ProviderInfo{
	{ID: "ollama", Label: "Ollama (local models)", BaseURL: "http://localhost:11434/v1", KeyEnv: "", DefaultModel: "qwen3"},
	{ID: "anthropic", Label: "Anthropic", BaseURL: "", KeyEnv: "ANTHROPIC_API_KEY", DefaultModel: "claude-opus-5-5"},
	{ID: "openai", Label: "OpenAI", BaseURL: "https://api.openai.com/v1", KeyEnv: "OPENAI_API_KEY", DefaultModel: ""},
	{ID: "openrouter", Label: "OpenRouter", BaseURL: "https://openrouter.ai/api/v1", KeyEnv: "OPENROUTER_API_KEY", DefaultModel: ""},
	{ID: "openai-compatible", Label: "Other OpenAI-compatible server (vLLM, LM Studio, ...)", BaseURL: "", KeyEnv: "", DefaultModel: ""},
}

// ProviderInfo describes a known provider.
type ProviderInfo struct {
	ID           string
	Label        string
	BaseURL      string
	KeyEnv       string // environment variable conventionally holding the key
	DefaultModel string
}

// Lookup returns the info for a provider id.
func Lookup(id string) (ProviderInfo, bool) {
	for _, p := range Providers {
		if p.ID == id {
			return p, true
		}
	}
	return ProviderInfo{}, false
}

// ErrNotConfigured means no provider has been chosen yet.
var ErrNotConfigured = errors.New("no model provider configured")

// New builds the provider described by c.
func New(c Config) (Provider, error) {
	if c.Provider == "" {
		return nil, ErrNotConfigured
	}
	info, ok := Lookup(c.Provider)
	if !ok {
		return nil, fmt.Errorf("unknown provider %q (want one of: %s)", c.Provider, providerIDs())
	}
	if c.Model == "" {
		c.Model = info.DefaultModel
	}
	if c.Model == "" {
		return nil, fmt.Errorf("provider %s: no model set (set `model:` in config.yaml or VIO_MODEL)", c.Provider)
	}
	if c.BaseURL == "" {
		c.BaseURL = info.BaseURL
	}
	switch c.Provider {
	case "anthropic":
		if c.APIKey == "" {
			return nil, fmt.Errorf("provider anthropic: no API key (set ANTHROPIC_API_KEY or run vio to set one up)")
		}
		return NewAnthropic(c), nil
	default:
		if c.BaseURL == "" {
			return nil, fmt.Errorf("provider %s: base_url is required", c.Provider)
		}
		if info.KeyEnv != "" && c.APIKey == "" {
			return nil, fmt.Errorf("provider %s: no API key (set %s or run vio to set one up)", c.Provider, info.KeyEnv)
		}
		return NewOpenAI(c), nil
	}
}

func providerIDs() string {
	ids := make([]string, len(Providers))
	for i, p := range Providers {
		ids[i] = p.ID
	}
	return strings.Join(ids, ", ")
}

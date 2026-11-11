package llm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// OpenAI speaks the OpenAI Chat Completions API, which Ollama, OpenRouter, vLLM,
// LM Studio and many gateways also implement. It uses only net/http.
type OpenAI struct {
	cfg    Config
	client *http.Client
}

// NewOpenAI returns an OpenAI-compatible provider.
func NewOpenAI(c Config) *OpenAI {
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	// No overall timeout: responses stream for as long as the model talks.
	// Cancellation comes from the request context.
	return &OpenAI{cfg: c, client: &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 5 * time.Minute, // local models can be slow to load
		IdleConnTimeout:       90 * time.Second,
	}}}
}

func (o *OpenAI) Name() string  { return o.cfg.Provider }
func (o *OpenAI) Model() string { return o.cfg.Model }

// Wire types (only the fields vio uses).

type oaMessage struct {
	Role       string       `json:"role"`
	Content    *string      `json:"content"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

type oaToolCall struct {
	Index    *int   `json:"index,omitempty"`
	ID       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Function struct {
		Name      string          `json:"name,omitempty"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
	} `json:"function"`
}

type oaTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type oaRequest struct {
	Model         string      `json:"model"`
	Messages      []oaMessage `json:"messages"`
	Tools         []oaTool    `json:"tools,omitempty"`
	Stream        bool        `json:"stream"`
	StreamOptions any         `json:"stream_options,omitempty"`
}

type oaChunk struct {
	Choices []struct {
		Delta struct {
			Content   string       `json:"content"`
			ToolCalls []oaToolCall `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func str(s string) *string { return &s }

func (o *OpenAI) buildRequest(req Request) oaRequest {
	out := oaRequest{Model: o.cfg.Model, Stream: true, StreamOptions: map[string]bool{"include_usage": true}}
	if req.System != "" {
		out.Messages = append(out.Messages, oaMessage{Role: "system", Content: str(req.System)})
	}
	for _, m := range req.Messages {
		switch m.Role {
		case RoleAssistant:
			am := oaMessage{Role: "assistant"}
			if m.Text != "" || len(m.ToolCalls) == 0 {
				am.Content = str(m.Text) // null when the turn is only tool calls
			}
			for _, tc := range m.ToolCalls {
				c := oaToolCall{ID: tc.ID, Type: "function"}
				c.Function.Name = tc.Name
				// The API wants arguments as a JSON-encoded string.
				args, _ := json.Marshal(string(tc.Args))
				c.Function.Arguments = args
				am.ToolCalls = append(am.ToolCalls, c)
			}
			out.Messages = append(out.Messages, am)
		case RoleUser:
			for _, tr := range m.ToolResults {
				out.Messages = append(out.Messages, oaMessage{Role: "tool", ToolCallID: tr.CallID, Content: str(tr.Content)})
			}
			if m.Text != "" {
				out.Messages = append(out.Messages, oaMessage{Role: "user", Content: str(m.Text)})
			}
		}
	}
	for _, t := range req.Tools {
		ot := oaTool{Type: "function"}
		ot.Function.Name, ot.Function.Description, ot.Function.Parameters = t.Name, t.Description, t.Schema
		out.Tools = append(out.Tools, ot)
	}
	return out
}

// Chat streams one completion.
func (o *OpenAI) Chat(ctx context.Context, req Request, onText func(string)) (Response, error) {
	body, err := json.Marshal(o.buildRequest(req))
	if err != nil {
		return Response{}, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "text/event-stream")
	if o.cfg.APIKey != "" {
		hr.Header.Set("Authorization", "Bearer "+o.cfg.APIKey)
	}
	resp, err := o.client.Do(hr)
	if err != nil {
		return Response{}, fmt.Errorf("%s: %w", o.cfg.Provider, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Response{}, fmt.Errorf("%s: HTTP %d: %s", o.cfg.Provider, resp.StatusCode, apiErrorMessage(msg))
	}
	return parseStream(resp.Body, onText)
}

func apiErrorMessage(body []byte) string {
	var e struct {
		Error any `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != nil {
		switch v := e.Error.(type) {
		case string:
			return v
		case map[string]any:
			if m, ok := v["message"].(string); ok {
				return m
			}
		}
	}
	return strings.TrimSpace(string(body))
}

// parseStream reads server-sent events and assembles the assistant message.
func parseStream(r io.Reader, onText func(string)) (Response, error) {
	type partial struct {
		id, name string
		args     strings.Builder
	}
	var (
		text   strings.Builder
		calls  = map[int]*partial{}
		finish string
		usage  Usage
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var ch oaChunk
		if err := json.Unmarshal([]byte(data), &ch); err != nil {
			return Response{}, fmt.Errorf("bad stream chunk: %w", err)
		}
		if ch.Error != nil {
			return Response{}, fmt.Errorf("model error: %s", ch.Error.Message)
		}
		if ch.Usage != nil {
			usage = Usage{InputTokens: ch.Usage.PromptTokens, OutputTokens: ch.Usage.CompletionTokens}
		}
		for _, c := range ch.Choices {
			if c.Delta.Content != "" {
				text.WriteString(c.Delta.Content)
				if onText != nil {
					onText(c.Delta.Content)
				}
			}
			for i, tc := range c.Delta.ToolCalls {
				idx := i
				if tc.Index != nil {
					idx = *tc.Index
				}
				p := calls[idx]
				if p == nil {
					p = &partial{}
					calls[idx] = p
				}
				if tc.ID != "" {
					p.id = tc.ID
				}
				if tc.Function.Name != "" {
					p.name = tc.Function.Name
				}
				p.args.WriteString(argFragment(tc.Function.Arguments))
			}
			if c.FinishReason != "" {
				finish = c.FinishReason
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Response{}, err
	}

	msg := Message{Role: RoleAssistant, Text: text.String()}
	idxs := make([]int, 0, len(calls))
	for i := range calls {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	for _, i := range idxs {
		p := calls[i]
		args := strings.TrimSpace(p.args.String())
		if args == "" {
			args = "{}"
		}
		id := p.id
		if id == "" {
			id = newCallID() // some servers (older Ollama) omit ids
		}
		msg.ToolCalls = append(msg.ToolCalls, ToolCall{ID: id, Name: p.name, Args: json.RawMessage(args)})
	}

	stop := StopEnd
	switch {
	case len(msg.ToolCalls) > 0:
		stop = StopToolUse
	case finish == "length":
		stop = StopMaxTokens
	case finish == "content_filter":
		stop = StopRefusal
	}
	return Response{Message: msg, StopReason: stop, Usage: usage}, nil
}

// argFragment returns tool arguments as text. OpenAI streams them as JSON string
// fragments; some servers (Ollama) send a whole JSON object instead.
func argFragment(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

func newCallID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "call_" + hex.EncodeToString(b[:])
}

// ListModels asks an OpenAI-compatible server for its models (used by setup).
func ListModels(ctx context.Context, baseURL, apiKey string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/models", nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(out.Data))
	for _, m := range out.Data {
		ids = append(ids, m.ID)
	}
	sort.Strings(ids)
	return ids, nil
}

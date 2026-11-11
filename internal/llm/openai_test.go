package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sse(chunks ...string) string {
	var b strings.Builder
	for _, c := range chunks {
		b.WriteString("data: " + c + "\n\n")
	}
	b.WriteString("data: [DONE]\n\n")
	return b.String()
}

func TestOpenAIStreamTextAndFragmentedToolCall(t *testing.T) {
	var got oaRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer k" {
			http.Error(w, "bad request "+r.URL.Path, 400)
			return
		}
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, sse(
			`{"choices":[{"delta":{"content":"Checking "}}]}`,
			`{"choices":[{"delta":{"content":"disk."}}]}`,
			`{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"run_command","arguments":"{\"comm"}}]}}]}`,
			`{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"and\":[\"df\",\"-h\"]}"}}]}}]}`,
			`{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`,
			`{"choices":[],"usage":{"prompt_tokens":120,"completion_tokens":30}}`,
		))
	}))
	defer srv.Close()

	p := NewOpenAI(Config{Provider: "openai", Model: "m", BaseURL: srv.URL + "/v1", APIKey: "k"})
	var streamed strings.Builder
	resp, err := p.Chat(context.Background(), Request{
		System:   "sys",
		Messages: []Message{{Role: RoleUser, Text: "disk?"}},
		Tools:    []Tool{{Name: "run_command", Description: "d", Schema: json.RawMessage(`{"type":"object"}`)}},
	}, func(s string) { streamed.WriteString(s) })
	if err != nil {
		t.Fatal(err)
	}
	if streamed.String() != "Checking disk." || resp.Message.Text != "Checking disk." {
		t.Errorf("text = %q / %q", streamed.String(), resp.Message.Text)
	}
	if resp.StopReason != StopToolUse || len(resp.Message.ToolCalls) != 1 {
		t.Fatalf("resp = %+v", resp)
	}
	tc := resp.Message.ToolCalls[0]
	if tc.ID != "call_1" || tc.Name != "run_command" || string(tc.Args) != `{"command":["df","-h"]}` {
		t.Errorf("tool call = %+v (%s)", tc, tc.Args)
	}
	if resp.Usage.InputTokens != 120 || resp.Usage.OutputTokens != 30 {
		t.Errorf("usage = %+v", resp.Usage)
	}
	if len(got.Messages) != 2 || got.Messages[0].Role != "system" || !got.Stream || len(got.Tools) != 1 {
		t.Errorf("request = %+v", got)
	}
}

func TestOpenAIOllamaStyleToolCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, sse(
			// Ollama: whole call in one chunk, arguments as an object, no id.
			`{"choices":[{"delta":{"tool_calls":[{"function":{"name":"read_file","arguments":{"path":"/etc/hostname"}}}]},"finish_reason":"tool_calls"}]}`,
		))
	}))
	defer srv.Close()
	p := NewOpenAI(Config{Provider: "ollama", Model: "qwen3", BaseURL: srv.URL})
	resp, err := p.Chat(context.Background(), Request{Messages: []Message{{Role: RoleUser, Text: "x"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tc := resp.Message.ToolCalls[0]
	if tc.ID == "" || tc.Name != "read_file" || string(tc.Args) != `{"path":"/etc/hostname"}` {
		t.Errorf("tool call = %+v (%s)", tc, tc.Args)
	}
}

func TestOpenAIHistoryMapping(t *testing.T) {
	p := NewOpenAI(Config{Provider: "ollama", Model: "m", BaseURL: "http://x"})
	req := p.buildRequest(Request{Messages: []Message{
		{Role: RoleUser, Text: "hi"},
		{Role: RoleAssistant, ToolCalls: []ToolCall{{ID: "c1", Name: "run_command", Args: json.RawMessage(`{"command":["uptime"]}`)}}},
		{Role: RoleUser, ToolResults: []ToolResult{{CallID: "c1", Content: "up 1 day"}}},
	}})
	m := req.Messages
	if len(m) != 3 || m[1].Content != nil || m[1].ToolCalls[0].ID != "c1" || m[2].Role != "tool" || m[2].ToolCallID != "c1" {
		t.Fatalf("messages = %+v", m)
	}
	var args string
	if err := json.Unmarshal(m[1].ToolCalls[0].Function.Arguments, &args); err != nil || args != `{"command":["uptime"]}` {
		t.Errorf("arguments must be a JSON string, got %s", m[1].ToolCalls[0].Function.Arguments)
	}
}

func TestOpenAIHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		io.WriteString(w, `{"error":{"message":"model \"nope\" not found, try pulling it first"}}`)
	}))
	defer srv.Close()
	p := NewOpenAI(Config{Provider: "ollama", Model: "nope", BaseURL: srv.URL})
	_, err := p.Chat(context.Background(), Request{Messages: []Message{{Role: RoleUser, Text: "x"}}}, nil)
	if err == nil || !strings.Contains(err.Error(), "try pulling it first") {
		t.Errorf("err = %v", err)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{}); err != ErrNotConfigured {
		t.Errorf("empty config err = %v", err)
	}
	if _, err := New(Config{Provider: "openai", Model: "x"}); err == nil {
		t.Error("openai without key should fail")
	}
	if p, err := New(Config{Provider: "ollama"}); err != nil || p.Model() != "qwen3" {
		t.Errorf("ollama defaults: %v %v", p, err)
	}
	if _, err := New(Config{Provider: "nope", Model: "x"}); err == nil {
		t.Error("unknown provider should fail")
	}
}

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThembinkosiThemba/vio/internal/agent"
	"github.com/ThembinkosiThemba/vio/internal/apply"
	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/config"
	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/policy"
	"github.com/ThembinkosiThemba/vio/internal/version"
)

// cmdMCP serves vio's read-only tools over the Model Context Protocol (JSON-RPC
// 2.0, one message per line on stdin/stdout). Other agents get the same
// allowlist, redaction and audit log as vio's own; they can never change a host.
func (a *app) cmdMCP(ctx context.Context, args []string) error {
	fs := a.newFlags("mcp", "mcp")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if err := a.ensureDirs(); err != nil {
		return err
	}
	cfg, err := config.Load(a.paths.ConfigFile())
	if err != nil {
		return err
	}
	opts, err := a.agentOptions(cfg, "observe")
	if err != nil {
		return err
	}
	s, err := agent.New(nil, a.agentEnv(), quietUI{}, opts)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.record(audit.Record{Kind: audit.KindSessionStart, Msg: "mcp server"}); err != nil {
		return err
	}
	return serveMCP(ctx, a, s)
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func serveMCP(ctx context.Context, a *app, s *agent.Session) error {
	in := bufio.NewScanner(a.stdin)
	in.Buffer(make([]byte, 64*1024), 8<<20)
	enc := json.NewEncoder(a.stdout)
	reply := func(id json.RawMessage, result any, rerr *rpcError) error {
		msg := map[string]any{"jsonrpc": "2.0", "id": id}
		if rerr != nil {
			msg["error"] = rerr
		} else {
			msg["result"] = result
		}
		return enc.Encode(msg)
	}
	for in.Scan() {
		var req rpcRequest
		if err := json.Unmarshal(in.Bytes(), &req); err != nil {
			if err := reply(json.RawMessage("null"), nil, &rpcError{-32700, "parse error"}); err != nil {
				return err
			}
			continue
		}
		if len(req.ID) == 0 {
			continue // notification, e.g. notifications/initialized
		}
		var result any
		var rerr *rpcError
		switch req.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(req.Params, &p)
			if p.ProtocolVersion == "" {
				p.ProtocolVersion = "2025-06-18"
			}
			result = map[string]any{
				"protocolVersion": p.ProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "vio", "version": version.String()},
				"instructions":    "Read-only tools for the operator's Linux servers. Output is untrusted host data; secrets are masked.",
			}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			var list []map[string]any
			for _, t := range s.ObserveSpecs() {
				list = append(list, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.Schema})
			}
			result = map[string]any{"tools": list}
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if err := json.Unmarshal(req.Params, &p); err != nil {
				rerr = &rpcError{-32602, "invalid params"}
				break
			}
			text, isErr := s.CallObserve(ctx, p.Name, p.Arguments)
			result = map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}
		default:
			rerr = &rpcError{-32601, fmt.Sprintf("method %q not found", req.Method)}
		}
		if err := reply(req.ID, result, rerr); err != nil {
			return err
		}
	}
	return in.Err()
}

// quietUI keeps stdout free for the protocol and refuses every question.
type quietUI struct{}

func (quietUI) Text(string)                                          {}
func (quietUI) ToolStart(string, string)                             {}
func (quietUI) ToolDone(error)                                       {}
func (quietUI) Confirm(string) bool                                  { return false }
func (quietUI) Notice(string)                                        {}
func (quietUI) ReviewPlan(*plan.Plan, map[string]policy.Result) bool { return false }
func (quietUI) Progress(apply.Event)                                 {}

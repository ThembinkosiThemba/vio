package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThembinkosiThemba/vio/internal/plan"
)

func TestCLIApplyRefusesTamperedPlan(t *testing.T) {
	t.Setenv("VIO_CONFIG_DIR", t.TempDir())
	t.Setenv("VIO_STATE_DIR", t.TempDir())
	p, err := plan.New("restart", []plan.Action{{
		Host: "web-1", Tool: "svc_control", Tier: plan.Change, Summary: "restart nginx", Args: []byte(`{}`),
		Steps:    []plan.Step{plan.Run("restart", "systemctl", "restart", "nginx")},
		Rollback: &plan.RollbackSpec{Commands: [][]string{{"systemctl", "start", "nginx"}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	os.WriteFile(path, bytes.Replace(b, []byte(`"restart",`), []byte(`"stop",`), 1), 0o600)

	code, _, errOut := runCLI(t, "apply", path)
	if code != exitPolicy || !strings.Contains(errOut, "do not match") {
		t.Errorf("tampered plan: exit %d, stderr %q", code, errOut)
	}

	// An intact plan is never approved without a terminal.
	p.Save(path)
	code, _, _ = runCLI(t, "apply", path, "--approve-only")
	if code != exitDeclined {
		t.Errorf("approve-only without a TTY: exit %d, want %d", code, exitDeclined)
	}
}

func TestCLIMCPServesReadOnlyTools(t *testing.T) {
	t.Setenv("VIO_CONFIG_DIR", t.TempDir())
	t.Setenv("VIO_STATE_DIR", t.TempDir())
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell_exec","arguments":{"command":["id"],"reason":"x"}}}
{"jsonrpc":"2.0","id":4,"method":"nope"}
`)
	w.Close()
	var out, errb bytes.Buffer
	if code := run(context.Background(), []string{"mcp"}, r, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	var replies []map[string]json.RawMessage
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad reply %q: %v", line, err)
		}
		replies = append(replies, m)
	}
	if len(replies) != 4 {
		t.Fatalf("want 4 replies (notifications get none), got %d:\n%s", len(replies), out.String())
	}
	list := string(replies[1]["result"])
	for _, want := range []string{`"run_command"`, `"check_run"`, `"net_listeners"`} {
		if !strings.Contains(list, want) {
			t.Errorf("tools/list missing %s", want)
		}
	}
	for _, banned := range []string{`"shell_exec"`, `"fs_write"`, `"add_host"`} {
		if strings.Contains(list, banned) {
			t.Errorf("tools/list exposes %s", banned)
		}
	}
	if !strings.Contains(string(replies[2]["result"]), `"isError":true`) {
		t.Errorf("change tool call should be refused: %s", replies[2]["result"])
	}
	if !strings.Contains(string(replies[3]["error"]), "-32601") {
		t.Errorf("unknown method: %s", replies[3]["error"])
	}
}

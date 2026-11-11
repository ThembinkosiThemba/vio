package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ThembinkosiThemba/vio/internal/audit"
)

func TestParseArgsInterspersed(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", "", "")
	trust := fs.Bool("trust", false, "")

	pos, err := parseArgs(fs, []string{"web-1", "--addr", "1.2.3.4", "extra", "--trust", "--", "--not-a-flag"})
	if err != nil {
		t.Fatal(err)
	}
	if *addr != "1.2.3.4" || !*trust {
		t.Errorf("flags not parsed: addr=%q trust=%v", *addr, *trust)
	}
	if want := []string{"web-1", "extra", "--not-a-flag"}; !slices.Equal(pos, want) {
		t.Errorf("positionals = %v; want %v", pos, want)
	}
}

// runCLI runs vio with isolated config and state dirs.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, nil, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCLIAskEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model    string `json:"model"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Model != "local-model" || len(req.Messages) != 2 || req.Messages[1].Content != "is web-1 ok?" {
			http.Error(w, "unexpected request", 400)
			return
		}
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"No servers yet, \"}}]}\n\n")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"add one first.\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()

	t.Setenv("VIO_CONFIG_DIR", t.TempDir())
	state := t.TempDir()
	t.Setenv("VIO_STATE_DIR", state)
	t.Setenv("VIO_PROVIDER", "openai-compatible")
	t.Setenv("VIO_MODEL", "local-model")
	t.Setenv("VIO_BASE_URL", srv.URL)

	code, out, errOut := runCLI(t, "ask", "is web-1 ok?")
	if code != 0 || !strings.Contains(out, "No servers yet, add one first.") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errOut)
	}
	recs, _ := audit.ReadAll(state + "/audit.jsonl")
	if len(recs) == 0 || recs[0].Kind != audit.KindSessionStart || recs[0].Msg != "local-model via openai-compatible" {
		t.Errorf("audit = %+v", recs)
	}
}

func TestCLIAskWithoutProvider(t *testing.T) {
	t.Setenv("VIO_CONFIG_DIR", t.TempDir())
	t.Setenv("VIO_STATE_DIR", t.TempDir())
	code, _, errOut := runCLI(t, "ask", "hi")
	if code != 1 || !strings.Contains(errOut, "vio setup") {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
}

func TestCLIInventoryFlow(t *testing.T) {
	t.Setenv("VIO_CONFIG_DIR", t.TempDir())
	state := t.TempDir()
	t.Setenv("VIO_STATE_DIR", state)

	steps := []struct {
		args     []string
		wantCode int
		wantOut  string
	}{
		{[]string{"init"}, 0, "created"},
		{[]string{"init"}, 0, "exists"},
		{[]string{"hosts", "add", "web-1", "--addr", "203.0.113.10", "--user", "deploy", "--tags", "prod,web"}, 0, "added web-1"},
		{[]string{"hosts", "add", "web-1", "--addr", "x", "--user", "y"}, 1, ""},
		{[]string{"hosts", "add", "--addr", "x"}, 2, ""},
		{[]string{"hosts", "ls"}, 0, "203.0.113.10:22"},
		{[]string{"hosts", "rm", "web-1"}, 0, "removed web-1"},
		{[]string{"hosts", "ls"}, 0, "no hosts yet"},
		{[]string{"log", "--verify"}, 0, "ok: 4 records"},
		{[]string{"apply", "plan.json"}, 1, ""},
		{[]string{"bogus"}, 2, ""},
	}
	for _, s := range steps {
		code, out, errOut := runCLI(t, s.args...)
		if code != s.wantCode {
			t.Fatalf("vio %s: exit %d, want %d\nstdout: %s\nstderr: %s", strings.Join(s.args, " "), code, s.wantCode, out, errOut)
		}
		if !strings.Contains(out, s.wantOut) {
			t.Fatalf("vio %s: stdout %q does not contain %q", strings.Join(s.args, " "), out, s.wantOut)
		}
	}

	recs, err := audit.ReadAll(state + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var tools []string
	for _, r := range recs {
		tools = append(tools, r.Tool)
	}
	if want := []string{"init", "init", "hosts.add", "hosts.rm"}; !slices.Equal(tools, want) {
		t.Errorf("audited tools = %v; want %v", tools, want)
	}
}

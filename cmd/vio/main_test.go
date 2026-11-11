package main

import (
	"bytes"
	"context"
	"flag"
	"io"
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

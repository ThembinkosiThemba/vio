// Command vio is a tiny, safety-first agent that runs and secures servers.
// See specs/plan.md for the architecture.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/config"
	"github.com/ThembinkosiThemba/vio/internal/version"
)

// Exit codes. See specs/plan.md §5.1.
const (
	exitOK       = 0
	exitError    = 1
	exitUsage    = 2
	exitPolicy   = 3
	exitDeclined = 4
	exitDrift    = 5
	exitRevert   = 6
)

const usage = `vio: the tiny server agent

Usage:
  vio                       start a chat with the agent
  vio <command> [arguments]

Commands:
  ask "<question>"          ask one question and exit (read-only)
  check [host] [--fix]      run the security baseline; --fix proposes a plan
  plan "<goal>" [-H host]   have the agent write a plan file (plan.json)
  apply plan.json           review and apply a plan with guards
  rollback <apply-id>       undo an applied plan
  watch [--every 1h]        re-check on a schedule; --webhook URL for alerts
  mcp                       serve read-only tools over MCP (stdio)
  setup                     choose the model provider
  reset [--yes]             clear config, API keys, servers, trusted keys, audit log
  init                      create config, inventory, and state directories
  attach [name]             attach the machine vio runs on (hosts add --local)
  hosts add <name> ...      add a host; details default to ~/.ssh/config
  hosts import [--yes]      add every host in ~/.ssh/config
  hosts ls                  list hosts
  hosts rm <name>           remove a host
  hosts trust <name>        verify and record a host's SSH key
  hosts check [name|group]  connect to hosts and report basic facts
  log [--verify] [-n N]     show or verify the audit log
  version                   print version information

Run 'vio <command> -h' for command help.
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		// The chat handles Ctrl-C itself: it stops the current reply, not vio.
		os.Exit(run(context.Background(), args, os.Stdin, os.Stdout, os.Stderr))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, args, os.Stdin, os.Stdout, os.Stderr))
}

// app carries the process-wide dependencies of every command.
type app struct {
	stdin          *os.File
	stdout, stderr io.Writer
	paths          config.Paths

	auditOnce sync.Once
	auditLog  *audit.Log
	auditErr  error

	pwMu  sync.Mutex
	pwMem map[string][]byte

	// in is the single buffered reader over stdin; every prompt must use it so
	// no command steals bytes buffered for another.
	in *bufio.Reader

	// pauseHook, when set, clears transient output (the chat spinner) before vio
	// prints a prompt of its own.
	pauseHook func()
}

func (a *app) pause() {
	if a.pauseHook != nil {
		a.pauseHook()
	}
}

// readLine reads one line of input (without the newline).
func (a *app) readLine() (string, error) {
	if a.in == nil {
		if a.stdin == nil {
			return "", io.EOF
		}
		a.in = bufio.NewReader(a.stdin)
	}
	line, err := a.in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	// Some shells (Windows PowerShell) prefix piped input with a UTF-8 BOM.
	return strings.TrimPrefix(strings.TrimRight(line, "\r\n"), "\ufeff"), nil
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return &usageError{fmt.Sprintf(format, a...)} }

// exitErr lets a command choose a specific exit code.
type exitErr struct {
	code int
	err  error
}

func (e *exitErr) Error() string { return e.err.Error() }

func run(ctx context.Context, args []string, stdin *os.File, stdout, stderr io.Writer) int {
	paths, err := config.DefaultPaths()
	if err != nil {
		fmt.Fprintf(stderr, "vio: %v\n", err)
		return exitError
	}
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr, paths: paths}
	if len(args) == 0 {
		return a.exitCode(a.cmdChat())
	}

	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "version", "--version":
		fmt.Fprintln(stdout, version.String())
		return exitOK
	case "init":
		err = a.cmdInit(rest)
	case "hosts":
		err = a.cmdHosts(ctx, rest)
	case "attach":
		err = a.cmdHosts(ctx, append([]string{"add", "--local"}, rest...))
	case "log":
		err = a.cmdLog(rest)
	case "ask":
		err = a.cmdAsk(ctx, rest)
	case "setup":
		_, err = a.setup(ctx)
	case "reset":
		err = a.cmdReset(rest)
	case "check":
		err = a.cmdCheck(ctx, rest)
	case "plan":
		err = a.cmdPlan(ctx, rest)
	case "apply":
		err = a.cmdApply(ctx, rest)
	case "rollback":
		err = a.cmdRollback(ctx, rest)
	case "watch":
		err = a.cmdWatch(ctx, rest)
	case "mcp":
		err = a.cmdMCP(ctx, rest)
	default:
		err = usagef("unknown command %q", cmd)
	}
	return a.exitCode(err)
}

func (a *app) exitCode(err error) int {
	if err == nil {
		return exitOK
	}
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(a.stderr, "vio: %v\nRun 'vio help' for usage.\n", err)
		return exitUsage
	}
	fmt.Fprintf(a.stderr, "vio: %v\n", err)
	var ee *exitErr
	if errors.As(err, &ee) {
		return ee.code
	}
	return exitError
}

// newFlags returns a FlagSet whose errors and help go to stderr.
func (a *app) newFlags(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.Usage = func() {
		fmt.Fprintf(a.stderr, "Usage: vio %s\n", synopsis)
		fs.PrintDefaults()
	}
	return fs
}

// parseArgs parses flags anywhere in args (stdlib flag stops at the first
// positional) and returns the positionals in order. Everything after "--" is positional.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, &usageError{err.Error()}
		}
		rest := fs.Args()
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

// audit returns the session's audit log, opening it on first use.
func (a *app) audit() (*audit.Log, error) {
	a.auditOnce.Do(func() {
		a.auditLog, a.auditErr = audit.Open(a.paths.AuditFile())
	})
	return a.auditLog, a.auditErr
}

// record appends to the audit log. Failing to audit is an error: vio does not
// act unaudited.
func (a *app) record(r audit.Record) error {
	l, err := a.audit()
	if err != nil {
		return err
	}
	_, err = l.Append(r)
	return err
}

func (a *app) isTTY() bool {
	return a.stdin != nil && term.IsTerminal(int(a.stdin.Fd()))
}

// confirm asks a yes/no question on the terminal, with optional detail text.
// Non-TTY input always answers no; so does cancelling the form.
func (a *app) confirm(question string, detail ...string) bool {
	if !a.isTTY() {
		return false
	}
	a.pause()
	ok := false
	c := huh.NewConfirm().Title(question).Affirmative("Yes").Negative("No").Value(&ok)
	if len(detail) > 0 {
		c = c.Description(strings.Join(detail, "\n"))
	}
	return runForm(huh.NewGroup(c)) == nil && ok
}

// passphrase prompts once per key file and remembers the answer for this process.
// Passphrases never leave memory.
func (a *app) passphrase(path string) ([]byte, error) {
	a.pwMu.Lock()
	defer a.pwMu.Unlock()
	if pw, ok := a.pwMem[path]; ok {
		return pw, nil
	}
	if !a.isTTY() {
		return nil, fmt.Errorf("ssh key %s is encrypted and stdin is not a terminal; load it into ssh-agent", path)
	}
	a.pause()
	var pw string
	if err := runForm(huh.NewGroup(huh.NewInput().
		Title("Passphrase for " + path).
		Description("Kept in memory for this session only.").
		EchoMode(huh.EchoModePassword).
		Value(&pw))); err != nil {
		return nil, err
	}
	if a.pwMem == nil {
		a.pwMem = map[string][]byte{}
	}
	a.pwMem[path] = []byte(pw)
	return []byte(pw), nil
}

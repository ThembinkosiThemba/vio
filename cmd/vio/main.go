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
  ask "<question>"          ask one question and exit
  setup                     choose the model provider
  init                      create config, inventory, and state directories
  hosts add <name> ...      add a host to the inventory
  hosts ls                  list hosts
  hosts rm <name>           remove a host
  hosts trust <name>        verify and record a host's SSH key
  hosts check [name|group]  connect to hosts and report basic facts
  log [--verify] [-n N]     show or verify the audit log
  version                   print version information

Coming in later phases:
  check, plan, apply, rollback

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
	return strings.TrimRight(line, "\r\n"), nil
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
	case "log":
		err = a.cmdLog(rest)
	case "ask":
		err = a.cmdAsk(ctx, rest)
	case "setup":
		_, err = a.setup(ctx)
	case "check":
		err = notYet(cmd, 1)
	case "plan", "apply", "rollback":
		err = notYet(cmd, 2)
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

func notYet(cmd string, phase int) error {
	return fmt.Errorf("'vio %s' is not implemented yet (roadmap phase %d, see specs/plan.md §11)", cmd, phase)
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

// confirm asks a yes/no question on the terminal. Non-TTY input always answers no.
func (a *app) confirm(question string) bool {
	if !a.isTTY() {
		return false
	}
	a.pause()
	fmt.Fprintf(a.stderr, "%s [y/N] ", question)
	line, _ := a.readLine()
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
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
	fmt.Fprintf(a.stderr, "Passphrase for %s: ", path)
	pw, err := term.ReadPassword(int(a.stdin.Fd()))
	fmt.Fprintln(a.stderr)
	if err != nil {
		return nil, err
	}
	if a.pwMem == nil {
		a.pwMem = map[string][]byte{}
	}
	a.pwMem[path] = pw
	return pw, nil
}

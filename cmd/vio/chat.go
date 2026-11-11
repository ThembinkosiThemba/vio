package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/ThembinkosiThemba/vio/internal/agent"
	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/config"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/transport"
	"github.com/ThembinkosiThemba/vio/internal/version"
)

const chatHelp = `
  /hosts    list your servers
  /model    show the model in use (change it with: vio setup)
  /clear    start a new conversation
  /usage    tokens used this session
  /exit     quit (or Ctrl-D)

  Ctrl-C stops the current reply.
`

// cmdChat is the interactive agent: what runs when you type `vio`.
func (a *app) cmdChat() error {
	ui := newTermUI(a)
	a.pauseHook = ui.pause
	s, cfg, err := a.newSession(context.Background(), ui, true)
	if err != nil {
		return err
	}
	defer func() {
		s.Close()
		_ = a.record(audit.Record{Kind: audit.KindSessionEnd})
	}()
	a.banner(ui, cfg)

	// Ctrl-C cancels the reply in progress; at the prompt it quits.
	var mu sync.Mutex
	var cancelTurn context.CancelFunc
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	go func() {
		for range sig {
			mu.Lock()
			c := cancelTurn
			mu.Unlock()
			if c != nil {
				c()
				continue
			}
			fmt.Fprintln(a.stdout)
			s.Close()
			os.Exit(exitOK)
		}
	}()

	for {
		fmt.Fprint(a.stdout, ui.st.bold("› "))
		line, err := a.readLine()
		if errors.Is(err, io.EOF) {
			fmt.Fprintln(a.stdout)
			return nil
		}
		if err != nil {
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" || strings.HasPrefix(line, "/") {
			if quit := a.slash(ui, s, cfg, line); quit {
				return nil
			}
			continue
		}

		ctx, cancel := context.WithCancel(context.Background())
		mu.Lock()
		cancelTurn = cancel
		mu.Unlock()

		fmt.Fprintln(a.stdout)
		ui.spin()
		err = s.Send(ctx, line)
		ui.pause()

		mu.Lock()
		cancelTurn = nil
		mu.Unlock()
		cancel()

		switch {
		case err == nil, errors.Is(err, agent.ErrStepLimit):
		case errors.Is(err, context.Canceled):
			ui.Notice("Stopped.")
		default:
			ui.fail(friendlyError(err, cfg))
		}
		fmt.Fprintln(a.stdout)
	}
}

// cmdAsk answers one question and exits.
func (a *app) cmdAsk(ctx context.Context, args []string) error {
	fs := a.newFlags("ask", `ask "<question>"`)
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	q := strings.TrimSpace(strings.Join(pos, " "))
	if q == "" {
		return usagef(`ask: expected a question, e.g. vio ask "is web-1 healthy?"`)
	}
	ui := newTermUI(a)
	a.pauseHook = ui.pause
	s, cfg, err := a.newSession(ctx, ui, a.isTTY())
	if err != nil {
		return err
	}
	defer s.Close()
	ui.spin()
	err = s.Send(ctx, q)
	ui.pause()
	if err != nil && !errors.Is(err, agent.ErrStepLimit) {
		return errors.New(friendlyError(err, cfg))
	}
	return nil
}

// newSession loads config (running setup on first use), builds the model
// client, and wires the agent to inventory, SSH, trust prompts, and audit.
func (a *app) newSession(ctx context.Context, ui agent.UI, allowSetup bool) (*agent.Session, config.Config, error) {
	if err := a.ensureDirs(); err != nil {
		return nil, config.Config{}, err
	}
	cfg, err := config.Load(a.paths.ConfigFile())
	if err != nil {
		return nil, cfg, err
	}
	if cfg.Provider == "" {
		if !allowSetup {
			return nil, cfg, errors.New("no model provider configured: run `vio setup`, or set VIO_PROVIDER and VIO_MODEL")
		}
		if cfg, err = a.setup(ctx); err != nil {
			return nil, cfg, err
		}
	}
	model, err := a.provider(cfg)
	if err != nil {
		return nil, cfg, fmt.Errorf("%w (run `vio setup` to fix)", err)
	}

	env := agent.Env{
		Inventory: a.loadInventory,
		AddHost: func(h inventory.Host) error {
			inv, err := a.loadInventory()
			if err != nil {
				return err
			}
			if err := inv.Add(h); err != nil {
				return err
			}
			if err := inv.Save(a.paths.HostsFile()); err != nil {
				return err
			}
			return a.record(audit.Record{Kind: audit.KindInventory, Tool: "hosts.add", Host: h.Name})
		},
		Trust: func(ctx context.Context, name string) error {
			inv, err := a.loadInventory()
			if err != nil {
				return err
			}
			hosts, err := inv.Resolve(name)
			if err != nil {
				return err
			}
			return a.trust(ctx, hosts[0], "")
		},
		Dial: func(ctx context.Context, h *inventory.Host) (transport.Executor, error) {
			return a.dial(ctx, h)
		},
		Record: a.record,
	}
	s, err := agent.New(model, env, ui, agent.Options{MaxSteps: cfg.Budget.MaxTurns})
	if err != nil {
		return nil, cfg, err
	}
	if err := a.record(audit.Record{Kind: audit.KindSessionStart, Msg: model.Model() + " via " + model.Name()}); err != nil {
		return nil, cfg, err
	}
	return s, cfg, nil
}

func (a *app) banner(ui *termUI, cfg config.Config) {
	inv, _ := a.loadInventory()
	n := 0
	if inv != nil {
		n = len(inv.Hosts)
	}
	servers := fmt.Sprintf("%d servers", n)
	if n == 1 {
		servers = "1 server"
	}
	ver := strings.Fields(version.String())[1]
	fmt.Fprintf(a.stdout, "\n  %s %s\n", ui.st.bold("vio"), ui.st.dim(ver+"  ·  "+cfg.Model+" via "+cfg.Provider+"  ·  "+servers))
	if n == 0 {
		fmt.Fprintf(a.stdout, "  %s\n\n", ui.st.dim("No servers yet. Try: add 203.0.113.10 as web-1, user deploy"))
	} else {
		fmt.Fprintf(a.stdout, "  %s\n\n", ui.st.dim("Ask about your servers. /help for commands."))
	}
}

// slash handles chat commands. It returns true to quit.
func (a *app) slash(ui *termUI, s *agent.Session, cfg config.Config, line string) bool {
	switch strings.Fields(line)[0] {
	case "/exit", "/quit", "exit", "quit":
		return true
	case "/help", "/?":
		fmt.Fprint(a.stdout, ui.st.dim(chatHelp)+"\n")
	case "/clear", "/new":
		if err := s.Reset(); err != nil {
			ui.fail(err.Error())
		} else {
			fmt.Fprintf(a.stdout, "  %s\n\n", ui.st.dim("New conversation."))
		}
	case "/hosts":
		inv, err := a.loadInventory()
		if err != nil {
			ui.fail(err.Error())
			break
		}
		if len(inv.Hosts) == 0 {
			fmt.Fprintf(a.stdout, "  %s\n\n", ui.st.dim("No servers yet."))
			break
		}
		for _, h := range inv.All() {
			fmt.Fprintf(a.stdout, "  %s  %s\n", ui.st.bold(h.Name), ui.st.dim(h.User+"@"+h.Endpoint()+"  "+strings.Join(h.Tags, ",")))
		}
		fmt.Fprintln(a.stdout)
	case "/model":
		fmt.Fprintf(a.stdout, "  %s %s\n\n", cfg.Model+" via "+cfg.Provider, ui.st.dim("(change with: vio setup)"))
	case "/usage":
		u := s.Usage()
		fmt.Fprintf(a.stdout, "  %s\n\n", ui.st.dim(fmt.Sprintf("%d input tokens, %d output tokens", u.InputTokens, u.OutputTokens)))
	default:
		fmt.Fprintf(a.stdout, "  %s\n\n", ui.st.dim("Unknown command. /help lists them."))
	}
	return false
}

// friendlyError adds a hint to common setup problems.
func friendlyError(err error, cfg config.Config) string {
	msg := err.Error()
	switch {
	case cfg.Provider == "ollama" && (strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused")):
		return msg + "\n  Is Ollama running? Start it with `ollama serve`."
	case strings.Contains(msg, "401") || strings.Contains(strings.ToLower(msg), "unauthorized"):
		return msg + "\n  Check your API key with `vio setup`."
	case strings.Contains(msg, "404") && cfg.Provider == "ollama":
		return msg + "\n  Pull the model first: ollama pull " + cfg.Model
	}
	return msg
}

// termUI renders the agent to a terminal.
type termUI struct {
	a        *app
	w        io.Writer
	st       style
	mu       sync.Mutex
	atStart  bool // cursor is at the start of a line
	spinStop chan struct{}
	spinDone chan struct{}
}

func newTermUI(a *app) *termUI {
	return &termUI{a: a, w: a.stdout, st: newStyle(a.stdout), atStart: true}
}

// spin shows a small activity indicator until the next output (TTY only).
func (u *termUI) spin() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.st.on || u.spinStop != nil {
		return
	}
	stop, done := make(chan struct{}), make(chan struct{})
	u.spinStop, u.spinDone = stop, done
	if !u.atStart {
		fmt.Fprintln(u.w)
		u.atStart = true
	}
	go func() {
		defer close(done)
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			fmt.Fprint(u.w, "\r  "+u.st.dim(frames[i%len(frames)]+" thinking"))
			select {
			case <-stop:
				fmt.Fprint(u.w, "\r\x1b[K")
				return
			case <-t.C:
			}
		}
	}()
}

// stopSpin must be called with u.mu held.
func (u *termUI) stopSpin() {
	if u.spinStop != nil {
		close(u.spinStop)
		<-u.spinDone
		u.spinStop, u.spinDone = nil, nil
	}
}

// pause stops the spinner and moves to a fresh line, before vio prompts.
func (u *termUI) pause() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopSpin()
	if !u.atStart {
		fmt.Fprintln(u.w)
		u.atStart = true
	}
}

func (u *termUI) Text(s string) {
	if s == "" {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopSpin()
	fmt.Fprint(u.w, s)
	u.atStart = strings.HasSuffix(s, "\n")
}

func (u *termUI) ToolStart(host, label string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopSpin()
	if !u.atStart {
		fmt.Fprintln(u.w)
	}
	if len(label) > 90 {
		label = label[:87] + "..."
	}
	fmt.Fprintf(u.w, "  %s %s  %s", u.st.green("●"), u.st.dim(host), u.st.dim(label))
	u.atStart = false
}

func (u *termUI) ToolDone(err error) {
	u.mu.Lock()
	if err != nil {
		msg := err.Error()
		if len(msg) > 80 {
			msg = msg[:77] + "..."
		}
		fmt.Fprint(u.w, "  "+u.st.red("✗ "+msg))
	}
	fmt.Fprintln(u.w)
	u.atStart = true
	u.mu.Unlock()
	u.spin() // the model is thinking again
}

func (u *termUI) Confirm(q string) bool {
	u.pause()
	return u.a.confirm("  " + u.st.bold("?") + " " + q)
}

func (u *termUI) Notice(s string) {
	u.pause()
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.w, "  %s\n", u.st.yellow(s))
}

func (u *termUI) fail(s string) {
	u.pause()
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.w, "  %s %s\n", u.st.red("✗"), s)
}

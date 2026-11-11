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

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"

	"github.com/ThembinkosiThemba/vio/internal/agent"
	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/config"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/transport"
	"github.com/ThembinkosiThemba/vio/internal/version"
)

// mode is what the agent may do. Until the plan/apply engine lands it can only look.
const mode = "read-only"

// chat is the interactive agent: what runs when you type `vio`.
type chat struct {
	a       *app
	ui      *termUI
	s       *agent.Session
	cfg     config.Config
	history []string
	tty     bool
}

func (a *app) cmdChat() error {
	ui := newTermUI(a)
	a.pauseHook = ui.pause
	if err := a.ensureDirs(); err != nil {
		return err
	}
	cfg, err := config.Load(a.paths.ConfigFile())
	if err != nil {
		return err
	}
	s, err := agent.New(nil, a.agentEnv(), ui, agent.Options{MaxSteps: cfg.Budget.MaxTurns})
	if err != nil {
		return err
	}
	c := &chat{a: a, ui: ui, s: s, cfg: cfg, tty: a.isTTY()}
	problem := c.loadModel()

	defer func() {
		s.Close()
		_ = a.record(audit.Record{Kind: audit.KindSessionEnd})
	}()
	if err := a.record(audit.Record{Kind: audit.KindSessionStart, Msg: c.modelLabel()}); err != nil {
		return err
	}

	c.printBanner()
	if problem != "" {
		c.callout(problem)
	}

	// Ctrl-C while a reply is streaming stops the reply. At the prompt the
	// input line handles Ctrl-C itself (it runs in raw mode).
	var mu sync.Mutex
	var cancelTurn context.CancelFunc
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	go func() {
		for range sig {
			mu.Lock()
			if cancelTurn != nil {
				cancelTurn()
			}
			mu.Unlock()
		}
	}()

	for {
		line, quit, err := c.read()
		if err != nil {
			return err
		}
		if quit {
			fmt.Fprintln(a.stdout)
			return nil
		}
		if line == "" {
			continue
		}
		c.history = append(c.history, line)

		if strings.HasPrefix(line, "/") || line == "exit" || line == "quit" {
			if c.command(line) {
				return nil
			}
			continue
		}

		ctx, cancel := context.WithCancel(context.Background())
		mu.Lock()
		cancelTurn = cancel
		mu.Unlock()
		c.turn(ctx, line)
		mu.Lock()
		cancelTurn = nil
		mu.Unlock()
		cancel()
	}
}

// read returns the next line: the styled prompt on a terminal, plain lines otherwise.
func (c *chat) read() (string, bool, error) {
	if c.tty {
		v, quit, err := readPrompt(c.history)
		return strings.TrimSpace(v), quit, err
	}
	fmt.Fprint(c.a.stdout, "› ")
	line, err := c.a.readLine()
	if errors.Is(err, io.EOF) {
		return "", true, nil
	}
	return strings.TrimSpace(line), false, err
}

// turn sends one message and prints the reply and its footer.
func (c *chat) turn(ctx context.Context, line string) {
	if c.s.Model() == nil {
		c.callout(c.noModelHint())
		return
	}
	start := time.Now()
	before := c.s.Usage()
	fmt.Fprintln(c.a.stdout)
	c.ui.begin(start)
	err := c.s.Send(ctx, line)
	c.ui.pause()
	after := c.s.Usage()

	switch {
	case err == nil, errors.Is(err, agent.ErrStepLimit):
	case errors.Is(err, context.Canceled):
		c.ui.Notice("Stopped.")
	default:
		c.ui.fail(friendlyError(err, c.cfg))
	}
	fmt.Fprintln(c.a.stdout)
	fmt.Fprintln(c.a.stdout, turnFooter(mode, c.modelLabel(),
		after.InputTokens-before.InputTokens, after.OutputTokens-before.OutputTokens, time.Since(start)))
	fmt.Fprintln(c.a.stdout)
}

// loadModel builds the provider from config. It returns a message for the
// operator when no usable model is configured.
func (c *chat) loadModel() string {
	if c.cfg.Provider == "" {
		c.s.SetModel(nil)
		return c.noModelHint()
	}
	p, err := c.a.provider(c.cfg)
	if err != nil {
		c.s.SetModel(nil)
		return err.Error() + ". Run /setup to fix it."
	}
	c.s.SetModel(p)
	return ""
}

func (c *chat) noModelHint() string {
	return "No model configured yet. Run /setup to choose Ollama, Anthropic, OpenAI, or any OpenAI-compatible server."
}

func (c *chat) modelLabel() string {
	if m := c.s.Model(); m != nil {
		return m.Model() + " · " + m.Name()
	}
	return "no model"
}

func (c *chat) printBanner() {
	inv, _ := c.a.loadInventory()
	var names []string
	if inv != nil {
		for _, h := range inv.All() {
			names = append(names, h.Name)
		}
	}
	ver := strings.Fields(version.String())[1]
	label := c.modelLabel()
	fmt.Fprint(c.a.stdout, banner(ver, label, mode, names, c.s.Model() != nil))
	fmt.Fprintf(c.a.stdout, "  %s\n\n", sFaint.Render("Ask about your servers in plain language. Type / for commands."))
}

func (c *chat) callout(msg string) {
	box := lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), false, false, false, true).
		BorderForeground(cWarn).
		PaddingLeft(1).
		MarginLeft(2).
		Foreground(cText).
		Width(min(termWidth(c.a.stdout)-4, 80)).
		Render(msg)
	fmt.Fprintf(c.a.stdout, "%s\n\n", box)
}

// command runs a / command. It returns true to quit.
func (c *chat) command(line string) bool {
	fields := strings.Fields(strings.TrimPrefix(line, "/"))
	if len(fields) == 0 {
		fields = []string{"help"}
	}
	name, args := fields[0], fields[1:]
	ctx := context.Background()
	out := c.a.stdout
	var err error

	switch name {
	case "exit", "quit", "q":
		return true
	case "help", "?":
		c.help()
	case "setup":
		var cfg config.Config
		if cfg, err = c.a.setup(ctx); err == nil {
			c.cfg = cfg
			if msg := c.loadModel(); msg != "" {
				c.callout(msg)
			}
		}
	case "model":
		if c.cfg.Provider == "" {
			return c.command("/setup")
		}
		if err = c.a.pickModel(ctx, &c.cfg, ""); err == nil {
			if msg := c.loadModel(); msg != "" {
				c.callout(msg)
			}
		}
	case "hosts", "servers":
		c.listHosts()
	case "add":
		err = c.addHost(ctx)
	case "trust":
		var h *inventory.Host
		if h, err = c.pickHost(args, "Which server's key do you want to trust?"); err == nil && h != nil {
			err = c.a.trust(ctx, h, "")
			fmt.Fprintln(out)
		}
	case "check":
		var hosts []*inventory.Host
		if hosts, err = c.hosts(args); err == nil && len(hosts) > 0 {
			err = c.a.checkHosts(ctx, hosts)
			fmt.Fprintln(out)
		}
	case "rm", "remove":
		var h *inventory.Host
		if h, err = c.pickHost(args, "Which server do you want to remove?"); err == nil && h != nil {
			if c.a.confirm("Remove "+h.Name+" from your inventory?", "Its SSH host key stays trusted.") {
				if err = c.a.hostsRemove([]string{h.Name}); err == nil {
					err = c.s.Refresh()
				}
			}
			fmt.Fprintln(out)
		}
	case "reset":
		var selected []string
		if !c.tty {
			err = errors.New("/reset needs a terminal; use `vio reset --yes` instead")
			break
		}
		if selected, err = c.a.askReset(); err != nil || selected == nil {
			if err == nil {
				fmt.Fprintf(out, "  %s\n\n", sFaint.Render("Nothing was changed."))
			}
			break
		}
		var removed []string
		removed, err = c.a.resetFiles(selected)
		printRemoved(c.a, removed)
		if err != nil {
			break
		}
		// Start over: drop connections and the conversation, reload settings.
		c.s.Close()
		if c.cfg, err = config.Load(c.a.paths.ConfigFile()); err != nil {
			break
		}
		if err = c.s.Reset(); err != nil {
			break
		}
		c.a.pwMem = nil
		c.printBanner()
		if msg := c.loadModel(); msg != "" {
			c.callout(msg)
		}
	case "clear", "new":
		if err = c.s.Reset(); err == nil {
			fmt.Fprintf(out, "  %s\n\n", sMuted.Render("Started a new conversation."))
		}
	case "usage":
		u := c.s.Usage()
		fmt.Fprintf(out, "  %s  %s\n\n", sMuted.Render("this session"), sBold.Render(fmt.Sprintf("↑ %s in  ↓ %s out", compact(u.InputTokens), compact(u.OutputTokens))))
	case "log":
		err = c.a.cmdLog([]string{"-n", "15"})
		fmt.Fprintln(out)
	case "verify":
		err = c.a.cmdLog([]string{"--verify"})
		fmt.Fprintln(out)
	case "version":
		fmt.Fprintf(out, "  %s\n\n", sMuted.Render(version.String()))
	default:
		fmt.Fprintf(out, "  %s %s\n\n", sWarn.Render("Unknown command /"+name+"."), sFaint.Render("Type / to see them all."))
	}

	switch {
	case err == nil:
	case errors.Is(err, errCancelled):
		fmt.Fprintf(out, "  %s\n\n", sFaint.Render("Cancelled."))
	default:
		c.ui.fail(err.Error())
		fmt.Fprintln(out)
	}
	return false
}

func (c *chat) help() {
	out := c.a.stdout
	fmt.Fprintf(out, "\n  %s\n", sBold.Render("Commands"))
	w := 0
	for _, cmd := range slashCommands {
		w = max(w, len(cmd.name)+len(cmd.args)+2)
	}
	for _, cmd := range slashCommands {
		name := "/" + cmd.name
		if cmd.args != "" {
			name += " " + cmd.args
		}
		fmt.Fprintf(out, "  %s%s%s\n", sAccent.Render(name), strings.Repeat(" ", w-len(name)+3), sMuted.Render(cmd.desc))
	}
	fmt.Fprintf(out, "\n  %s\n", sBold.Render("Shortcuts"))
	for _, s := range [][2]string{
		{"/", "open the command menu"},
		{"↑ ↓", "previous messages"},
		{"ctrl+c", "stop a reply; on an empty line, quit"},
	} {
		fmt.Fprintf(out, "  %s%s%s\n", sAccent.Render(s[0]), strings.Repeat(" ", w-len([]rune(s[0]))+3), sMuted.Render(s[1]))
	}
	fmt.Fprintln(out)
}

func (c *chat) listHosts() {
	out := c.a.stdout
	inv, err := c.a.loadInventory()
	if err != nil {
		c.ui.fail(err.Error())
		return
	}
	if len(inv.Hosts) == 0 {
		fmt.Fprintf(out, "  %s\n\n", sMuted.Render("No servers yet. Add one with /add, or just tell me about it."))
		return
	}
	nameW, epW := 4, 8
	for _, h := range inv.All() {
		nameW = max(nameW, len(h.Name))
		epW = max(epW, len(h.User)+1+len(h.Endpoint()))
	}
	for _, h := range inv.All() {
		ep := h.User + "@" + h.Endpoint()
		fmt.Fprintf(out, "  %s  %s  %s\n",
			sBold.Render(h.Name+strings.Repeat(" ", nameW-len(h.Name))),
			sMuted.Render(ep+strings.Repeat(" ", epW-len(ep))),
			sFaint.Render(strings.Join(h.Tags, ", ")))
	}
	fmt.Fprintln(out)
}

// hosts resolves names, or every host when none are given.
func (c *chat) hosts(args []string) ([]*inventory.Host, error) {
	inv, err := c.a.loadInventory()
	if err != nil {
		return nil, err
	}
	if len(inv.Hosts) == 0 {
		fmt.Fprintf(c.a.stdout, "  %s\n\n", sMuted.Render("No servers yet. Add one with /add."))
		return nil, nil
	}
	return inv.Resolve(args...)
}

// pickHost returns the named host, or asks the operator to choose one.
func (c *chat) pickHost(args []string, title string) (*inventory.Host, error) {
	inv, err := c.a.loadInventory()
	if err != nil {
		return nil, err
	}
	if len(args) > 0 {
		hs, err := inv.Resolve(args[0])
		if err != nil {
			return nil, err
		}
		return hs[0], nil
	}
	all := inv.All()
	switch len(all) {
	case 0:
		fmt.Fprintf(c.a.stdout, "  %s\n\n", sMuted.Render("No servers yet. Add one with /add."))
		return nil, nil
	case 1:
		return all[0], nil
	}
	if !c.tty {
		return nil, errors.New("name a server, e.g. /trust web-1")
	}
	opts := make([]huh.Option[string], len(all))
	for i, h := range all {
		opts[i] = huh.NewOption(h.Name+"  "+sFaint.Render(h.User+"@"+h.Endpoint()), h.Name)
	}
	var name string
	if err := runForm(huh.NewGroup(huh.NewSelect[string]().Title(title).Options(opts...).Value(&name))); err != nil {
		return nil, err
	}
	return inv.Hosts[name], nil
}

// addHost collects a server's details in a form, saves it, and offers to trust it.
func (c *chat) addHost(ctx context.Context) error {
	if !c.tty {
		return errors.New("/add needs a terminal; use `vio hosts add` instead")
	}
	inv, err := c.a.loadInventory()
	if err != nil {
		return err
	}
	var name, addr, user, port, identity, tags string
	port = "22"
	user = "root"
	err = runForm(huh.NewGroup(
		huh.NewInput().Title("Name").Description("A short name, like web-1.").Value(&name).
			Validate(func(s string) error {
				s = strings.TrimSpace(s)
				if err := inventory.ValidateName(s); err != nil {
					return errors.New("use lowercase letters, digits, '.', '_' or '-'")
				}
				if inv.Hosts[s] != nil {
					return errors.New(s + " already exists")
				}
				return nil
			}),
		huh.NewInput().Title("Address").Description("IP address or DNS name.").Placeholder("203.0.113.10").Value(&addr).Validate(required("an address")),
		huh.NewInput().Title("SSH user").Value(&user).Validate(required("a user")),
		huh.NewInput().Title("SSH port").Value(&port).Validate(func(s string) error {
			var p int
			if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &p); err != nil || p < 1 || p > 65535 {
				return errors.New("enter a port between 1 and 65535")
			}
			return nil
		}),
		huh.NewInput().Title("Private key").Description("Optional. Leave empty to use ssh-agent or ~/.ssh/id_*.").Placeholder("~/.ssh/id_ed25519").Value(&identity),
		huh.NewInput().Title("Tags").Description("Optional, comma-separated.").Placeholder("prod, web").Value(&tags),
	))
	if err != nil {
		return err
	}
	h := inventory.Host{Name: strings.TrimSpace(name), Addr: strings.TrimSpace(addr), User: strings.TrimSpace(user), Identity: strings.TrimSpace(identity)}
	fmt.Sscanf(strings.TrimSpace(port), "%d", &h.Port)
	if h.Port == 22 {
		h.Port = 0
	}
	for _, t := range strings.Split(tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			h.Tags = append(h.Tags, t)
		}
	}
	if err := c.a.agentEnv().AddHost(h); err != nil {
		return err
	}
	if err := c.s.Refresh(); err != nil {
		return err
	}
	fmt.Fprintf(c.a.stdout, "  %s Added %s %s\n", sAccent.Render("✓"), sBold.Render(h.Name), sMuted.Render(h.User+"@"+h.Endpoint()))
	if c.a.confirm("Verify and trust its SSH key now?", "vio connects only to servers whose key you have trusted.") {
		if err := c.a.trust(ctx, c.mustHost(h.Name), ""); err != nil {
			return err
		}
	}
	fmt.Fprintln(c.a.stdout)
	return nil
}

func (c *chat) mustHost(name string) *inventory.Host {
	inv, _ := c.a.loadInventory()
	return inv.Hosts[name]
}

// agentEnv wires the agent to inventory files, SSH, trust prompts and audit.
func (a *app) agentEnv() agent.Env {
	return agent.Env{
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
	if err := a.ensureDirs(); err != nil {
		return err
	}
	cfg, err := config.Load(a.paths.ConfigFile())
	if err != nil {
		return err
	}
	if cfg.Provider == "" {
		return errors.New("no model provider configured: run `vio` and use /setup, or set VIO_PROVIDER and VIO_MODEL")
	}
	model, err := a.provider(cfg)
	if err != nil {
		return fmt.Errorf("%w (run `vio setup` to fix)", err)
	}
	ui := newTermUI(a)
	a.pauseHook = ui.pause
	s, err := agent.New(model, a.agentEnv(), ui, agent.Options{MaxSteps: cfg.Budget.MaxTurns})
	if err != nil {
		return err
	}
	defer s.Close()
	if err := a.record(audit.Record{Kind: audit.KindSessionStart, Msg: model.Model() + " via " + model.Name()}); err != nil {
		return err
	}
	ui.begin(time.Now())
	err = s.Send(ctx, q)
	ui.pause()
	if err != nil && !errors.Is(err, agent.ErrStepLimit) {
		return errors.New(friendlyError(err, cfg))
	}
	return nil
}

// friendlyError adds a hint to common setup problems.
func friendlyError(err error, cfg config.Config) string {
	msg := err.Error()
	switch {
	case errors.Is(err, agent.ErrNoModel):
		return "No model configured. Run /setup."
	case cfg.Provider == "ollama" && (strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused")):
		return msg + "\n    Is Ollama running? Start it with `ollama serve`."
	case strings.Contains(msg, "401") || strings.Contains(strings.ToLower(msg), "unauthorized"):
		return msg + "\n    Check your API key with /setup."
	case strings.Contains(msg, "404") && cfg.Provider == "ollama":
		return msg + "\n    Pull the model first: ollama pull " + cfg.Model
	}
	return msg
}

// termUI renders the agent's activity to a terminal.
type termUI struct {
	a        *app
	w        io.Writer
	color    bool
	mu       sync.Mutex
	atStart  bool // cursor is at the start of a line
	started  time.Time
	spinStop chan struct{}
	spinDone chan struct{}

	toolHost, toolLabel string
	toolStart           time.Time
}

func newTermUI(a *app) *termUI {
	return &termUI{a: a, w: a.stdout, color: newStyle(a.stdout).on, atStart: true}
}

// begin starts a turn: the spinner shows elapsed time from start.
func (u *termUI) begin(start time.Time) {
	u.mu.Lock()
	u.started = start
	u.mu.Unlock()
	u.spin()
}

// spin shows "thinking" with a timer until the next output (TTY only).
func (u *termUI) spin() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.color || u.spinStop != nil {
		return
	}
	if !u.atStart {
		fmt.Fprintln(u.w)
		u.atStart = true
	}
	stop, done := make(chan struct{}), make(chan struct{})
	u.spinStop, u.spinDone = stop, done
	started := u.started
	go func() {
		defer close(done)
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			el := ""
			if !started.IsZero() {
				el = "  " + roundDuration(time.Since(started).Truncate(time.Second))
			}
			fmt.Fprint(u.w, "\r  "+sAccent.Render(frames[i%len(frames)])+" "+sMuted.Render("thinking")+sFaint.Render(el))
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

// Text streams model output, indented under the operator's message.
func (u *termUI) Text(s string) {
	if s == "" {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopSpin()
	var b strings.Builder
	for _, r := range s {
		if u.atStart && r != '\n' {
			b.WriteString("  ")
			u.atStart = false
		}
		b.WriteRune(r)
		if r == '\n' {
			u.atStart = true
		}
	}
	fmt.Fprint(u.w, b.String())
}

func (u *termUI) ToolStart(host, label string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.stopSpin()
	if !u.atStart {
		fmt.Fprintln(u.w)
	}
	if len(label) > 80 {
		label = label[:77] + "..."
	}
	u.toolHost, u.toolLabel, u.toolStart = host, label, time.Now()
	fmt.Fprint(u.w, "  "+sFaint.Render("○")+" "+sMuted.Render(host)+"  "+sFaint.Render(label))
	u.atStart = false
}

func (u *termUI) ToolDone(err error) {
	u.mu.Lock()
	d := roundDuration(time.Since(u.toolStart))
	line := "  " + sAccent.Render("✓") + " " + sMuted.Render(u.toolHost) + "  " + sFaint.Render(u.toolLabel) + "  " + sFaint.Render(d)
	if err != nil {
		msg := err.Error()
		if len(msg) > 70 {
			msg = msg[:67] + "..."
		}
		line = "  " + sErr.Render("✗") + " " + sMuted.Render(u.toolHost) + "  " + sFaint.Render(u.toolLabel) + "  " + sErr.Render(msg)
	}
	if u.color {
		fmt.Fprint(u.w, "\r\x1b[K"+line+"\n") // replace the ○ line in place
	} else {
		fmt.Fprintln(u.w, line)
	}
	u.atStart = true
	u.mu.Unlock()
	u.spin() // the model is thinking again
}

func (u *termUI) Confirm(q string) bool {
	u.pause()
	return u.a.confirm(q)
}

func (u *termUI) Notice(s string) {
	u.pause()
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.w, "  %s\n", sWarn.Render(s))
}

func (u *termUI) fail(s string) {
	u.pause()
	u.mu.Lock()
	defer u.mu.Unlock()
	fmt.Fprintf(u.w, "  %s %s\n", sErr.Render("✗"), s)
}

// termWidth returns the terminal width, or 80.
func termWidth(w io.Writer) int {
	if f, ok := w.(*os.File); ok {
		if width, _, err := termSize(f); err == nil && width > 0 {
			return width
		}
	}
	return 80
}

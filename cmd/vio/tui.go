package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// Palette: monochrome to match the brand, with green as the only accent.
var (
	cText   = lipgloss.AdaptiveColor{Light: "#0A0A0A", Dark: "#EDEDED"}
	cMuted  = lipgloss.AdaptiveColor{Light: "#5F5F5F", Dark: "#A1A1A1"}
	cFaint  = lipgloss.AdaptiveColor{Light: "#8F8F8F", Dark: "#6B6B6B"}
	cLine   = lipgloss.AdaptiveColor{Light: "#DCDCDC", Dark: "#2E2E2E"}
	cAccent = lipgloss.AdaptiveColor{Light: "#15803D", Dark: "#4ADE80"}
	cWarn   = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"}
	cErr    = lipgloss.AdaptiveColor{Light: "#DC2626", Dark: "#F87171"}

	sBold   = lipgloss.NewStyle().Bold(true).Foreground(cText)
	sMuted  = lipgloss.NewStyle().Foreground(cMuted)
	sFaint  = lipgloss.NewStyle().Foreground(cFaint)
	sAccent = lipgloss.NewStyle().Foreground(cAccent)
	sWarn   = lipgloss.NewStyle().Foreground(cWarn)
	sErr    = lipgloss.NewStyle().Foreground(cErr)
)

// formTheme styles huh forms in the same palette.
func formTheme() *huh.Theme {
	t := huh.ThemeBase()
	t.Focused.Base = t.Focused.Base.BorderForeground(cLine)
	t.Focused.Title = t.Focused.Title.Foreground(cText).Bold(true)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(cText).Bold(true)
	t.Focused.Description = t.Focused.Description.Foreground(cMuted)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(cAccent)
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(cAccent)
	t.Focused.Option = t.Focused.Option.Foreground(cText)
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(cFaint)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(cFaint)
	t.Focused.ErrorIndicator = t.Focused.ErrorIndicator.Foreground(cErr)
	t.Focused.ErrorMessage = t.Focused.ErrorMessage.Foreground(cErr)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(cAccent)
	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(cAccent)
	t.Focused.TextInput.Placeholder = t.Focused.TextInput.Placeholder.Foreground(cFaint)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#0A0A0A"}).Background(cAccent)
	t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(cMuted).Background(lipgloss.AdaptiveColor{Light: "#EBEBEB", Dark: "#1F1F1F"})
	t.Blurred = t.Focused
	t.Blurred.Base = t.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Title = t.Blurred.Title.Foreground(cMuted).Bold(false)
	return t
}

// runForm runs a huh form; Ctrl-C/Esc returns errCancelled.
func runForm(groups ...*huh.Group) error {
	err := huh.NewForm(groups...).WithTheme(formTheme()).WithShowHelp(false).Run()
	if errors.Is(err, huh.ErrUserAborted) {
		return errCancelled
	}
	return err
}

var errCancelled = errors.New("cancelled")

// banner is shown when the chat opens.
func banner(version, model, mode string, hosts []string, configured bool) string {
	label := lipgloss.NewStyle().Foreground(cFaint).Width(7)
	row := func(k, v string) string { return label.Render(k) + v }

	modelLine := sBold.Render(model)
	if !configured {
		modelLine = sWarn.Render("not configured") + sFaint.Render("  ·  /setup")
	}
	hostLine := sFaint.Render("none yet  ·  /add")
	if len(hosts) > 0 {
		shown := hosts
		if len(shown) > 4 {
			shown = append(shown[:4:4], fmt.Sprintf("+%d", len(hosts)-4))
		}
		hostLine = sMuted.Render(strings.Join(shown, ", "))
	}

	title := sBold.Render("vio") + "  " + sFaint.Render(version)
	body := strings.Join([]string{
		title,
		sMuted.Render("the tiny server agent"),
		"",
		row("model", modelLine),
		row("mode", sAccent.Render("●")+" "+sMuted.Render(mode)),
		row("hosts", hostLine),
	}, "\n")
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cLine).
		Padding(0, 2).
		MarginLeft(1).
		Render(body)
	return "\n" + box + "\n"
}

// turnFooter is printed after every reply.
func turnFooter(mode, model string, in, out int, d time.Duration) string {
	sep := sFaint.Render("  ·  ")
	parts := []string{
		sAccent.Render("●") + " " + sMuted.Render(mode),
		sMuted.Render(model),
		sMuted.Render("↑ "+compact(in)) + " " + sMuted.Render("↓ "+compact(out)),
		sMuted.Render(roundDuration(d)),
	}
	return "  " + strings.Join(parts, sep)
}

func compact(n int) string {
	switch {
	case n <= 0:
		return "0"
	case n < 1000:
		return fmt.Sprintf("%d", n)
	case n < 100_000:
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	default:
		return fmt.Sprintf("%dk", n/1000)
	}
}

func roundDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
}

// slashCommand is one entry in the / menu.
type slashCommand struct {
	name, args, desc string
}

var slashCommands = []slashCommand{
	{"help", "", "show commands and shortcuts"},
	{"setup", "", "choose the model provider"},
	{"model", "", "switch the model"},
	{"hosts", "", "list your servers"},
	{"add", "", "add a server"},
	{"trust", "[name]", "verify and trust a server's SSH key"},
	{"check", "[name]", "run the security baseline (no model)"},
	{"ping", "[name]", "test the connection to servers"},
	{"rm", "[name]", "remove a server"},
	{"rollback", "<id>", "undo an applied plan"},
	{"clear", "", "start a new conversation"},
	{"reset", "", "forget settings, keys, servers and history"},
	{"usage", "", "tokens used this session"},
	{"log", "", "recent audit log entries"},
	{"verify", "", "verify the audit log's hash chain"},
	{"version", "", "show version information"},
	{"exit", "", "quit vio"},
}

func matchCommands(prefix string) []slashCommand {
	var out []slashCommand
	for _, c := range slashCommands {
		if strings.HasPrefix(c.name, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// promptModel is the input line: a text field with a / command menu and history.
type promptModel struct {
	ti      textinput.Model
	history []string
	hpos    int
	draft   string
	sugg    []slashCommand
	sel     int
	value   string
	done    bool
	quit    bool
	width   int
}

func newPrompt(history []string) promptModel {
	ti := textinput.New()
	ti.Prompt = "› "
	ti.PromptStyle = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	ti.TextStyle = lipgloss.NewStyle().Foreground(cText)
	ti.PlaceholderStyle = lipgloss.NewStyle().Foreground(cFaint)
	ti.Placeholder = "Ask about your servers, or type / for commands"
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(cAccent)
	ti.Focus()
	return promptModel{ti: ti, history: history, hpos: len(history)}
}

func (m promptModel) Init() tea.Cmd { return textinput.Blink }

func (m promptModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.ti.Width = max(10, msg.Width-4)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			if m.ti.Value() != "" {
				m.ti.SetValue("")
				m.refresh()
				return m, nil
			}
			m.quit = true
			return m, tea.Quit
		case "ctrl+d":
			if m.ti.Value() == "" {
				m.quit = true
				return m, tea.Quit
			}
		case "esc":
			if len(m.sugg) > 0 {
				m.ti.SetValue("")
				m.refresh()
				return m, nil
			}
		case "tab":
			if len(m.sugg) > 0 {
				m.complete()
				return m, nil
			}
		case "up":
			if len(m.sugg) > 0 {
				m.sel = (m.sel - 1 + len(m.sugg)) % len(m.sugg)
				return m, nil
			}
			if m.hpos > 0 {
				if m.hpos == len(m.history) {
					m.draft = m.ti.Value()
				}
				m.hpos--
				m.ti.SetValue(m.history[m.hpos])
				m.ti.CursorEnd()
			}
			return m, nil
		case "down":
			if len(m.sugg) > 0 {
				m.sel = (m.sel + 1) % len(m.sugg)
				return m, nil
			}
			if m.hpos < len(m.history) {
				m.hpos++
				if m.hpos == len(m.history) {
					m.ti.SetValue(m.draft)
				} else {
					m.ti.SetValue(m.history[m.hpos])
				}
				m.ti.CursorEnd()
			}
			return m, nil
		case "enter":
			v := strings.TrimSpace(m.ti.Value())
			// Enter on a partial command picks the highlighted one.
			if len(m.sugg) > 0 && v != "/"+m.sugg[m.sel].name {
				c := m.sugg[m.sel]
				if c.args != "" {
					m.complete()
					return m, nil
				}
				v = "/" + c.name
			}
			if v == "" {
				return m, nil
			}
			m.value, m.done = v, true
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.ti, cmd = m.ti.Update(msg)
	m.refresh()
	return m, cmd
}

func (m *promptModel) complete() {
	m.ti.SetValue("/" + m.sugg[m.sel].name + " ")
	m.ti.CursorEnd()
	m.refresh()
}

// refresh recomputes the / menu from the current input.
func (m *promptModel) refresh() {
	v := m.ti.Value()
	if !strings.HasPrefix(v, "/") || strings.Contains(v, " ") {
		m.sugg, m.sel = nil, 0
		return
	}
	m.sugg = matchCommands(v[1:])
	if m.sel >= len(m.sugg) {
		m.sel = 0
	}
}

func (m promptModel) View() string {
	if m.quit {
		return ""
	}
	if m.done {
		return sAccent.Bold(true).Render("› ") + sBold.Render(m.value) + "\n"
	}
	var b strings.Builder
	b.WriteString(m.ti.View())
	if len(m.sugg) > 0 {
		b.WriteString("\n")
		nameW := 0
		for _, c := range m.sugg {
			nameW = max(nameW, len(c.name)+len(c.args)+2)
		}
		for i, c := range m.sugg {
			name := "/" + c.name
			if c.args != "" {
				name += " " + c.args
			}
			pad := strings.Repeat(" ", nameW-len(name)+2)
			if i == m.sel {
				b.WriteString("\n  " + sAccent.Render("› "+name) + pad + sMuted.Render(c.desc))
			} else {
				b.WriteString("\n    " + sMuted.Render(name) + pad + sFaint.Render(c.desc))
			}
		}
		b.WriteString("\n\n  " + sFaint.Render("↑↓ select  ·  tab complete  ·  enter run  ·  esc close"))
	} else if m.ti.Value() == "" {
		b.WriteString("\n  " + sFaint.Render("/ commands  ·  ↑ history  ·  ctrl+c quit"))
	}
	return b.String()
}

// readPrompt shows the input line and returns what the operator typed.
// quit reports Ctrl-C/Ctrl-D on an empty line.
func readPrompt(history []string) (value string, quit bool, err error) {
	res, err := tea.NewProgram(newPrompt(history)).Run()
	if err != nil {
		return "", false, err
	}
	m := res.(promptModel)
	return m.value, m.quit, nil
}

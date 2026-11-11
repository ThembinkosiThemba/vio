package main

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func keys(m promptModel, ks ...tea.KeyMsg) promptModel {
	for _, k := range ks {
		next, _ := m.Update(k)
		m = next.(promptModel)
	}
	return m
}

func typed(s string) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)} }

var (
	kEnter = tea.KeyMsg{Type: tea.KeyEnter}
	kTab   = tea.KeyMsg{Type: tea.KeyTab}
	kUp    = tea.KeyMsg{Type: tea.KeyUp}
	kDown  = tea.KeyMsg{Type: tea.KeyDown}
	kCtrlC = tea.KeyMsg{Type: tea.KeyCtrlC}
	kEsc   = tea.KeyMsg{Type: tea.KeyEsc}
)

func TestPromptSlashMenuFilters(t *testing.T) {
	m := keys(newPrompt(nil), typed("/"))
	if len(m.sugg) != len(slashCommands) {
		t.Fatalf("'/' should list every command, got %d", len(m.sugg))
	}
	m = keys(m, typed("ve"))
	if len(m.sugg) != 2 || m.sugg[0].name != "verify" || m.sugg[1].name != "version" {
		t.Fatalf("'/ve' suggestions = %+v", m.sugg)
	}
	if !strings.Contains(m.View(), "/verify") {
		t.Error("menu not rendered")
	}
}

func TestPromptEnterRunsHighlightedCommand(t *testing.T) {
	m := keys(newPrompt(nil), typed("/ve"), kDown, kEnter)
	if !m.done || m.value != "/version" {
		t.Fatalf("value = %q done = %v", m.value, m.done)
	}
}

func TestPromptEnterCompletesCommandWithArgs(t *testing.T) {
	m := keys(newPrompt(nil), typed("/tr"), kEnter)
	if m.done || m.ti.Value() != "/trust " {
		t.Fatalf("want completion to '/trust ', got %q (done=%v)", m.ti.Value(), m.done)
	}
	m = keys(m, typed("web-1"), kEnter)
	if !m.done || m.value != "/trust web-1" {
		t.Fatalf("value = %q", m.value)
	}
}

func TestPromptTabCompletes(t *testing.T) {
	m := keys(newPrompt(nil), typed("/se"), kTab)
	if m.ti.Value() != "/setup " || len(m.sugg) != 0 {
		t.Fatalf("value = %q sugg = %d", m.ti.Value(), len(m.sugg))
	}
}

func TestPromptHistory(t *testing.T) {
	m := keys(newPrompt([]string{"first", "second"}), typed("draft"), kUp)
	if m.ti.Value() != "second" {
		t.Fatalf("up = %q", m.ti.Value())
	}
	m = keys(m, kUp, kDown, kDown)
	if m.ti.Value() != "draft" {
		t.Fatalf("down past newest should restore the draft, got %q", m.ti.Value())
	}
}

func TestPromptCtrlCClearsThenQuits(t *testing.T) {
	m := keys(newPrompt(nil), typed("hello"), kCtrlC)
	if m.quit || m.ti.Value() != "" {
		t.Fatalf("first ctrl+c should clear, got quit=%v value=%q", m.quit, m.ti.Value())
	}
	m = keys(m, kCtrlC)
	if !m.quit {
		t.Fatal("ctrl+c on an empty line should quit")
	}
}

func TestPromptEscClosesMenu(t *testing.T) {
	m := keys(newPrompt(nil), typed("/h"), kEsc)
	if len(m.sugg) != 0 || m.ti.Value() != "" {
		t.Fatalf("esc should close the menu, got %q", m.ti.Value())
	}
}

func TestPromptPlainMessage(t *testing.T) {
	m := keys(newPrompt(nil), typed("is web-1 ok?"), kEnter)
	if !m.done || m.value != "is web-1 ok?" || len(m.sugg) != 0 {
		t.Fatalf("value = %q", m.value)
	}
}

func TestFooterAndFormatting(t *testing.T) {
	f := turnFooter("read-only", "qwen3 · ollama", 1234, 56, 4200*time.Millisecond)
	for _, want := range []string{"read-only", "qwen3 · ollama", "1.2k", "56", "4.2s"} {
		if !strings.Contains(f, want) {
			t.Errorf("footer %q missing %q", f, want)
		}
	}
	if compact(0) != "0" || compact(999) != "999" || compact(250_000) != "250k" {
		t.Error("compact formatting")
	}
	if roundDuration(800*time.Millisecond) != "800ms" || roundDuration(95*time.Second) != "1m35s" {
		t.Error("duration formatting")
	}
}

func TestBannerShowsSetupHintWhenUnconfigured(t *testing.T) {
	b := banner("v0.1.0", "no model", "read-only", nil, false)
	for _, want := range []string{"vio", "not configured", "/setup", "read-only", "/add"} {
		if !strings.Contains(b, want) {
			t.Errorf("banner missing %q:\n%s", want, b)
		}
	}
}

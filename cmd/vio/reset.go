package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/ThembinkosiThemba/vio/internal/audit"
)

// resetItem is something `reset` can clear.
type resetItem struct {
	key, label string
	paths      []string
}

func (a *app) resetItems() []resetItem {
	return []resetItem{
		{"model", "Model provider and API keys", []string{a.paths.ConfigFile(), a.paths.CredentialsFile()}},
		{"hosts", "Servers", []string{a.paths.HostsFile()}},
		{"keys", "Trusted SSH host keys (vio's own; ~/.ssh is never touched)", []string{a.paths.KnownHostsFile()}},
		{"policy", "Policy rules (policy.yaml)", []string{a.paths.PolicyFile()}},
		{"audit", "Audit log", []string{a.paths.AuditFile()}},
	}
}

func allResetKeys(items []resetItem) []string {
	keys := make([]string, len(items))
	for i, it := range items {
		keys[i] = it.key
	}
	return keys
}

// resetFiles deletes the files for the selected items and records the reset.
// It returns the paths that were removed.
func (a *app) resetFiles(selected []string) ([]string, error) {
	var removed []string
	for _, it := range a.resetItems() {
		if !contains(selected, it.key) {
			continue
		}
		for _, p := range it.paths {
			err := os.Remove(p)
			switch {
			case err == nil:
				removed = append(removed, p)
			case errors.Is(err, fs.ErrNotExist):
			default:
				return removed, err
			}
		}
	}
	// Recorded after deleting, so a cleared audit log starts with this entry.
	args, _ := json.Marshal(map[string][]string{"cleared": selected})
	return removed, a.record(audit.Record{Kind: audit.KindInventory, Tool: "reset", Args: args})
}

// askReset lets the operator pick what to clear and confirm. It returns the
// selected keys, or nil if they backed out.
func (a *app) askReset() ([]string, error) {
	items := a.resetItems()
	opts := make([]huh.Option[string], len(items))
	for i, it := range items {
		opts[i] = huh.NewOption(it.label, it.key).Selected(true)
	}
	var selected []string
	if err := runForm(huh.NewGroup(huh.NewMultiSelect[string]().
		Title("What should vio forget?").
		Description("Space to toggle, enter to continue.").
		Options(opts...).
		Value(&selected))); err != nil {
		return nil, err
	}
	if len(selected) == 0 {
		return nil, nil
	}
	var files []string
	for _, it := range items {
		if contains(selected, it.key) {
			for _, p := range it.paths {
				if _, err := os.Stat(p); err == nil {
					files = append(files, "  "+p)
				}
			}
		}
	}
	if len(files) == 0 {
		fmt.Fprintf(a.stdout, "  %s\n\n", sMuted.Render("Nothing to clear; those are already empty."))
		return nil, nil
	}
	detail := append([]string{"This permanently deletes:"}, files...)
	if !a.confirm("Reset vio?", detail...) {
		return nil, nil
	}
	return selected, nil
}

// cmdReset implements `vio reset`.
func (a *app) cmdReset(args []string) error {
	fs := a.newFlags("reset", "reset [--yes]")
	yes := fs.Bool("yes", false, "clear everything without asking (config, keys, servers, trusted keys, audit log)")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	var selected []string
	switch {
	case *yes:
		selected = allResetKeys(a.resetItems())
	case a.isTTY():
		var err error
		if selected, err = a.askReset(); err != nil {
			return err
		}
		if selected == nil {
			fmt.Fprintf(a.stdout, "  %s\n", sMuted.Render("Nothing was changed."))
			return nil
		}
	default:
		return usagef("reset: stdin is not a terminal; pass --yes to clear everything")
	}
	removed, err := a.resetFiles(selected)
	printRemoved(a, removed)
	return err
}

func printRemoved(a *app, removed []string) {
	if len(removed) == 0 {
		fmt.Fprintf(a.stdout, "  %s\n\n", sMuted.Render("Nothing to clear."))
		return
	}
	fmt.Fprintf(a.stdout, "  %s Reset. Removed:\n", sAccent.Render("✓"))
	for _, p := range removed {
		fmt.Fprintf(a.stdout, "    %s\n", sFaint.Render(p))
	}
	fmt.Fprintln(a.stdout)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

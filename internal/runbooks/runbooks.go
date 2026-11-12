// Package runbooks loads markdown runbooks: built-in ones embedded in the
// binary and the operator's own from ~/.config/vio/runbooks. The agent sees
// only names and descriptions and reads a body on demand. Runbooks guide
// reasoning; they grant no permissions. See specs/plan.md §5.15.
package runbooks

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

//go:embed builtin/*.md
var builtin embed.FS

// Runbook is one markdown runbook.
type Runbook struct {
	Name, Description, AppliesTo string
	Body                         string
	User                         bool // from the operator's directory
}

// Load returns the built-in runbooks plus those in dir (which may not exist).
// An operator runbook with a built-in's name replaces it.
func Load(dir string) ([]Runbook, error) {
	byName := map[string]Runbook{}
	entries, _ := fs.ReadDir(builtin, "builtin")
	for _, e := range entries {
		b, err := builtin.ReadFile("builtin/" + e.Name())
		if err != nil {
			return nil, err
		}
		r, err := Parse(string(b))
		if err != nil {
			return nil, fmt.Errorf("runbook %s: %w", e.Name(), err)
		}
		byName[r.Name] = r
	}
	if dir != "" {
		files, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".md") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, f.Name()))
			if err != nil {
				return nil, err
			}
			r, err := Parse(string(b))
			if err != nil {
				return nil, fmt.Errorf("runbook %s: %w", f.Name(), err)
			}
			r.User = true
			byName[r.Name] = r
		}
	}
	out := make([]Runbook, 0, len(byName))
	for _, r := range byName {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Runbook) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Parse reads a runbook with "---" frontmatter (name, description, applies_to).
func Parse(s string) (Runbook, error) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return Runbook{}, errors.New("missing --- frontmatter")
	}
	front, body, ok := strings.Cut(s[4:], "\n---\n")
	if !ok {
		return Runbook{}, errors.New("unterminated frontmatter")
	}
	var r Runbook
	for _, line := range strings.Split(front, "\n") {
		k, v, _ := strings.Cut(line, ":")
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "name":
			r.Name = v
		case "description":
			r.Description = v
		case "applies_to":
			r.AppliesTo = v
		}
	}
	if r.Name == "" {
		return Runbook{}, errors.New("frontmatter needs a name")
	}
	r.Body = strings.TrimSpace(body)
	return r, nil
}

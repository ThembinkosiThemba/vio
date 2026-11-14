// Package sshconfig reads the subset of OpenSSH client config (~/.ssh/config)
// that vio needs to attach a host by its ssh alias: Host, HostName, User, Port,
// IdentityFile and Include. It is deliberately small and dependency-free; any
// construct it cannot honour is reported as a warning, never silently ignored.
package sshconfig

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// maxIncludeDepth matches OpenSSH's READCONF_MAX_DEPTH.
const maxIncludeDepth = 16

// Config is a parsed client config.
type Config struct {
	blocks []block
	home   string
}

// block is one Host (or Match) section. Options outside any section belong to
// an implicit "Host *" block.
type block struct {
	patterns []string
	match    bool // Match blocks are recorded but never evaluated
	opts     []option
}

type option struct {
	key  string // lowercased keyword
	args []string
}

// Host is what the config says about one alias, after first-match-wins
// resolution. Empty fields were not set by any matching block.
type Host struct {
	Alias    string
	HostName string
	User     string
	Port     int
	Identity string // first IdentityFile, with ~ and %d/%h/%% expanded
	// Known reports whether a non-wildcard Host pattern names this alias.
	Known bool
	// Warnings lists settings that apply to this alias but that vio ignores.
	Warnings []string
}

// Addr is HostName, or the alias itself when HostName is unset (as ssh does).
func (h Host) Addr() string {
	if h.HostName != "" {
		return h.HostName
	}
	return h.Alias
}

// DefaultPath returns ~/.ssh/config.
func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("sshconfig: %w", err)
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

// Load reads path and every file it includes. Relative Include paths resolve
// against ~/.ssh, like OpenSSH's user config. A missing file is an empty config.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("sshconfig: %w", err)
	}
	defer f.Close()
	return parseNamed(f, path)
}

// Parse reads a config from r. Include directives resolve as in Load.
func Parse(r io.Reader) (*Config, error) {
	return parseNamed(r, "<config>")
}

func parseNamed(r io.Reader, name string) (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("sshconfig: %w", err)
	}
	p := &parser{home: home, sshDir: filepath.Join(home, ".ssh")}
	if err := p.parse(r, name, []string{"*"}, 0); err != nil {
		return nil, err
	}
	return &Config{blocks: p.blocks, home: home}, nil
}

type parser struct {
	home, sshDir string
	blocks       []block
}

func (p *parser) open(patterns []string, match bool) {
	p.blocks = append(p.blocks, block{patterns: patterns, match: match})
}

// parse appends the blocks of r. An included file starts in its includer's
// section, and the includer's section resumes after it, as in OpenSSH.
func (p *parser) parse(r io.Reader, name string, section []string, depth int) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("sshconfig: %s: Include nested too deeply", name)
	}
	p.open(section, false)
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		key, args, err := splitLine(sc.Text())
		if err != nil {
			return fmt.Errorf("sshconfig: %s:%d: %w", name, n, err)
		}
		if key == "" {
			continue
		}
		if len(args) == 0 {
			return fmt.Errorf("sshconfig: %s:%d: %s has no value", name, n, key)
		}
		switch key {
		case "host":
			p.open(args, false)
		case "match":
			p.open(nil, true)
		case "include":
			cur := p.blocks[len(p.blocks)-1]
			if cur.match {
				// The include is conditional on a Match vio cannot evaluate.
				cur.opts = append(cur.opts, option{key, args})
				p.blocks[len(p.blocks)-1] = cur
				continue
			}
			if err := p.include(args, cur.patterns, depth); err != nil {
				return fmt.Errorf("sshconfig: %s:%d: %w", name, n, err)
			}
			p.open(cur.patterns, false)
		default:
			b := &p.blocks[len(p.blocks)-1]
			b.opts = append(b.opts, option{key, args})
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("sshconfig: %s: %w", name, err)
	}
	return nil
}

func (p *parser) include(globs, section []string, depth int) error {
	for _, g := range globs {
		g = expandTilde(g, p.home)
		if !filepath.IsAbs(g) {
			g = filepath.Join(p.sshDir, g)
		}
		matches, err := filepath.Glob(g)
		if err != nil {
			return fmt.Errorf("include %s: %w", g, err)
		}
		slices.Sort(matches)
		for _, m := range matches {
			f, err := os.Open(m)
			if err != nil {
				return fmt.Errorf("include: %w", err)
			}
			err = p.parse(f, m, section, depth+1)
			f.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// splitLine returns the lowercased keyword and its arguments. Blank lines and
// comments return an empty keyword. Both "Key value" and "Key=value" are accepted.
func splitLine(line string) (string, []string, error) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", nil, nil
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), nil, nil
	}
	key, rest := line[:i], strings.TrimLeft(line[i:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	args, err := fields(rest)
	return strings.ToLower(key), args, err
}

// fields splits on whitespace, honouring double quotes. A '#' starting an
// unquoted field begins a trailing comment.
func fields(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inField, quoted := false, false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			inField = true
		case !quoted && (r == ' ' || r == '\t'):
			if inField {
				out = append(out, cur.String())
				cur.Reset()
				inField = false
			}
		case !quoted && !inField && r == '#':
			return out, nil
		default:
			cur.WriteRune(r)
			inField = true
		}
	}
	if quoted {
		return nil, errors.New("unterminated quote")
	}
	if inField {
		out = append(out, cur.String())
	}
	return out, nil
}

// ignored are keywords that change where or how ssh connects. vio does not
// honour them, so a host they apply to gets a warning.
var ignored = map[string]string{
	"proxyjump":       "ProxyJump",
	"proxycommand":    "ProxyCommand",
	"hostkeyalias":    "HostKeyAlias",
	"certificatefile": "CertificateFile",
	"localcommand":    "LocalCommand",
	"remotecommand":   "RemoteCommand",
}

// Lookup resolves alias the way ssh does: for each keyword, the first value
// from a matching block wins.
func (c *Config) Lookup(alias string) (Host, error) {
	h := Host{Alias: alias}
	seen := map[string]bool{}
	hasMatch := false
	for _, b := range c.blocks {
		if b.match {
			hasMatch = true
			continue
		}
		if !matches(b.patterns, alias) {
			continue
		}
		if slices.ContainsFunc(b.patterns, func(p string) bool { return strings.EqualFold(p, alias) }) {
			h.Known = true
		}
		for _, o := range b.opts {
			v := o.args[0]
			// IdentityFile accumulates in ssh; vio keeps the first one.
			if o.key == "identityfile" {
				if h.Identity == "" && !strings.EqualFold(v, "none") {
					h.Identity = expandTilde(expandTokens(v, alias, c.home), c.home)
				}
				continue
			}
			if seen[o.key] {
				continue
			}
			seen[o.key] = true
			switch o.key {
			case "hostname":
				h.HostName = strings.Trim(expandTokens(v, alias, c.home), "[]")
			case "user":
				h.User = v
			case "port":
				p, err := strconv.Atoi(v)
				if err != nil || p < 1 || p > 65535 {
					return Host{}, fmt.Errorf("sshconfig: %s: invalid Port %q", alias, v)
				}
				h.Port = p
			default:
				if name, ok := ignored[o.key]; ok && !strings.EqualFold(v, "none") {
					h.Warnings = append(h.Warnings, name+" is set in ssh config; vio connects directly and ignores it")
				}
			}
		}
	}
	if hasMatch {
		h.Warnings = append(h.Warnings, "ssh config has Match blocks; vio does not evaluate them, so ssh may connect differently")
	}
	return h, nil
}

// Aliases returns every concrete alias (no wildcards or negations) named by a
// Host line, in file order, without duplicates.
func (c *Config) Aliases() []string {
	var out []string
	for _, b := range c.blocks {
		if b.match {
			continue
		}
		for _, p := range b.patterns {
			if strings.ContainsAny(p, "*?!") || slices.Contains(out, p) {
				continue
			}
			out = append(out, p)
		}
	}
	return out
}

// matches applies ssh's Host semantics: some positive pattern matches and no
// negated pattern does.
func matches(patterns []string, host string) bool {
	ok := false
	for _, p := range patterns {
		if neg, found := strings.CutPrefix(p, "!"); found {
			if wildcard(neg, host) {
				return false
			}
			continue
		}
		if wildcard(p, host) {
			ok = true
		}
	}
	return ok
}

// wildcard matches '*' (any run) and '?' (one character), case-insensitively.
func wildcard(pattern, s string) bool {
	pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			for i := len(s); i >= 0; i-- {
				if wildcard(pattern[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
		default:
			if s == "" || s[0] != pattern[0] {
				return false
			}
		}
		pattern, s = pattern[1:], s[1:]
	}
	return s == ""
}

// expandTokens expands %h (host), %d (home) and %%. Other tokens are left as is.
func expandTokens(s, host, home string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'h':
			b.WriteString(host)
		case 'd':
			b.WriteString(home)
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('%')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func expandTilde(p, home string) string {
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}

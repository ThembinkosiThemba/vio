// Package inventory loads and edits hosts.yaml: the servers vio may connect to.
package inventory

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"regexp"
	"slices"
	"strconv"

	"go.yaml.in/yaml/v3"

	"github.com/ThembinkosiThemba/vio/internal/fsutil"
)

// Host is one server. Notes are operator-authored context for the agent; unlike
// anything read from the host itself, they are trusted.
type Host struct {
	Name     string   `yaml:"-"`
	Addr     string   `yaml:"addr"`
	Port     int      `yaml:"port,omitempty"`
	User     string   `yaml:"user"`
	Identity string   `yaml:"identity,omitempty"`
	Tags     []string `yaml:"tags,omitempty,flow"`
	Notes    string   `yaml:"notes,omitempty"`
}

// Endpoint returns host:port for dialing.
func (h Host) Endpoint() string {
	port := h.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(h.Addr, strconv.Itoa(port))
}

// Inventory is the parsed hosts.yaml.
type Inventory struct {
	Hosts  map[string]*Host    `yaml:"hosts"`
	Groups map[string][]string `yaml:"groups,omitempty"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidateName reports whether s is usable as a host or group name.
func ValidateName(s string) error {
	if !nameRE.MatchString(s) {
		return fmt.Errorf("invalid name %q: use lowercase letters, digits, '.', '_', '-' (max 63)", s)
	}
	return nil
}

// Validate checks a single host definition.
func (h *Host) Validate() error {
	if err := ValidateName(h.Name); err != nil {
		return err
	}
	if h.Addr == "" {
		return fmt.Errorf("host %s: addr is required", h.Name)
	}
	if h.User == "" {
		return fmt.Errorf("host %s: user is required", h.Name)
	}
	if h.Port < 0 || h.Port > 65535 {
		return fmt.Errorf("host %s: port %d out of range", h.Name, h.Port)
	}
	return nil
}

// Validate checks every host and that groups only reference known hosts.
func (inv *Inventory) Validate() error {
	for name, h := range inv.Hosts {
		h.Name = name
		if err := h.Validate(); err != nil {
			return err
		}
	}
	for g, members := range inv.Groups {
		if err := ValidateName(g); err != nil {
			return fmt.Errorf("group: %w", err)
		}
		if _, clash := inv.Hosts[g]; clash {
			return fmt.Errorf("group %s: name is also a host", g)
		}
		for _, m := range members {
			if _, ok := inv.Hosts[m]; !ok {
				return fmt.Errorf("group %s: unknown host %q", g, m)
			}
		}
	}
	return nil
}

// Load reads hosts.yaml. A missing file is an empty inventory.
func Load(path string) (*Inventory, error) {
	inv := &Inventory{}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("read inventory: %w", err)
	default:
		if err := yaml.Unmarshal(data, inv); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if inv.Hosts == nil {
		inv.Hosts = map[string]*Host{}
	}
	if err := inv.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return inv, nil
}

// Save writes the inventory atomically with owner-only permissions.
func (inv *Inventory) Save(path string) error {
	if err := inv.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(inv)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, data, 0o600)
}

// Add inserts a new host. It refuses to overwrite an existing one.
func (inv *Inventory) Add(h Host) error {
	if err := h.Validate(); err != nil {
		return err
	}
	if _, ok := inv.Hosts[h.Name]; ok {
		return fmt.Errorf("host %s already exists", h.Name)
	}
	if _, ok := inv.Groups[h.Name]; ok {
		return fmt.Errorf("%s is already a group name", h.Name)
	}
	inv.Hosts[h.Name] = &h
	return nil
}

// Remove deletes a host and drops it from every group.
func (inv *Inventory) Remove(name string) error {
	if _, ok := inv.Hosts[name]; !ok {
		return fmt.Errorf("unknown host %s", name)
	}
	delete(inv.Hosts, name)
	for g, members := range inv.Groups {
		inv.Groups[g] = slices.DeleteFunc(members, func(m string) bool { return m == name })
	}
	return nil
}

// Resolve expands host and group names into hosts, deduplicated, in the order
// given. No selectors means every host, sorted by name.
func (inv *Inventory) Resolve(selectors ...string) ([]*Host, error) {
	if len(selectors) == 0 {
		return inv.All(), nil
	}
	var out []*Host
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, inv.Hosts[name])
		}
	}
	for _, s := range selectors {
		if _, ok := inv.Hosts[s]; ok {
			add(s)
			continue
		}
		members, ok := inv.Groups[s]
		if !ok {
			return nil, fmt.Errorf("unknown host or group %q", s)
		}
		for _, m := range members {
			add(m)
		}
	}
	return out, nil
}

// All returns every host sorted by name.
func (inv *Inventory) All() []*Host {
	names := make([]string, 0, len(inv.Hosts))
	for n := range inv.Hosts {
		names = append(names, n)
	}
	slices.Sort(names)
	out := make([]*Host, len(names))
	for i, n := range names {
		out[i] = inv.Hosts[n]
	}
	return out
}

// Skeleton is the commented hosts.yaml written by `vio init`.
const Skeleton = `# vio inventory. Add hosts with: vio hosts add <name> --addr <ip> --user <user>
#
# hosts:
#   web-1:
#     addr: 203.0.113.10
#     port: 22
#     user: deploy
#     identity: ~/.ssh/id_ed25519
#     tags: [prod, web]
#     notes: |
#       Caddy reverse proxy for app.example.com.
# groups:
#   prod: [web-1]
hosts: {}
`

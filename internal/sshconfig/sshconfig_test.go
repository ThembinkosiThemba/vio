package sshconfig

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeHome points the user's home at a temp dir with a ~/.ssh folder.
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

// realWorld is shaped like a typical operator config: globals, wildcards,
// negation, Include, Match, IPv6, non-22 ports and quoting.
const realWorld = `# global defaults
ServerAliveInterval 30
Include conf.d/*.conf

Host web-1
    HostName 203.0.113.10
    User deploy
    Port 2222
    IdentityFile ~/.ssh/id_web
    IdentityFile ~/.ssh/id_fallback

Host web-2 web-3
    HostName %h.example.com
    User=deploy

Host db-1
  Hostname "2001:db8::5"
  ProxyJump bastion

Host v6-bracketed
  HostName [2001:db8::6]

Host *.internal !secret.internal
  User ops
  Port 2200

Host bastion
  HostName bastion.example.com # trailing comment

Match host web-1 exec "true"
  User nobody

Host *
  User fallback
  Port 22
  IdentityFile none
`

const included = `Host from-include
  HostName 198.51.100.7
  User inc
`

func load(t *testing.T) *Config {
	t.Helper()
	home := fakeHome(t)
	dir := filepath.Join(home, ".ssh", "conf.d")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.conf"), []byte(included), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".ssh", "config")
	if err := os.WriteFile(path, []byte(realWorld), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLookup(t *testing.T) {
	c := load(t)
	home, _ := os.UserHomeDir()
	tests := []struct {
		alias    string
		want     Host
		warnings []string // substrings, beyond the Match warning every host gets
	}{
		{"web-1", Host{HostName: "203.0.113.10", User: "deploy", Port: 2222, Identity: filepath.Join(home, ".ssh", "id_web"), Known: true}, nil},
		{"web-3", Host{HostName: "web-3.example.com", User: "deploy", Port: 22, Known: true}, nil},
		{"db-1", Host{HostName: "2001:db8::5", User: "fallback", Port: 22, Known: true}, []string{"ProxyJump"}},
		{"v6-bracketed", Host{HostName: "2001:db8::6", User: "fallback", Port: 22, Known: true}, nil},
		{"app.internal", Host{User: "ops", Port: 2200}, nil},
		{"secret.internal", Host{User: "fallback", Port: 22}, nil},
		{"bastion", Host{HostName: "bastion.example.com", User: "fallback", Port: 22, Known: true}, nil},
		{"from-include", Host{HostName: "198.51.100.7", User: "inc", Port: 22, Known: true}, nil},
		{"WEB-1", Host{HostName: "203.0.113.10", User: "deploy", Port: 2222, Identity: filepath.Join(home, ".ssh", "id_web"), Known: true}, nil},
		{"nowhere", Host{User: "fallback", Port: 22}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.alias, func(t *testing.T) {
			got, err := c.Lookup(tt.alias)
			if err != nil {
				t.Fatal(err)
			}
			tt.want.Alias = tt.alias
			warnings := got.Warnings
			got.Warnings = nil
			if got.Alias != tt.want.Alias || got.HostName != tt.want.HostName || got.User != tt.want.User ||
				got.Port != tt.want.Port || got.Identity != tt.want.Identity || got.Known != tt.want.Known {
				t.Errorf("Lookup(%s) =\n %+v\nwant\n %+v", tt.alias, got, tt.want)
			}
			if !slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, "Match") }) {
				t.Errorf("warnings %q lack the Match warning", warnings)
			}
			for _, w := range tt.warnings {
				if !slices.ContainsFunc(warnings, func(s string) bool { return strings.Contains(s, w) }) {
					t.Errorf("warnings %q lack %q", warnings, w)
				}
			}
			if len(warnings) != 1+len(tt.warnings) {
				t.Errorf("warnings = %q", warnings)
			}
		})
	}
}

func TestAliases(t *testing.T) {
	got := load(t).Aliases()
	want := []string{"from-include", "web-1", "web-2", "web-3", "db-1", "v6-bracketed", "bastion"}
	if !slices.Equal(got, want) {
		t.Errorf("Aliases = %v; want %v", got, want)
	}
}

func TestAddr(t *testing.T) {
	if got := (Host{Alias: "web-1"}).Addr(); got != "web-1" {
		t.Errorf("Addr without HostName = %q", got)
	}
	if got := (Host{Alias: "web-1", HostName: "10.0.0.1"}).Addr(); got != "10.0.0.1" {
		t.Errorf("Addr = %q", got)
	}
}

func TestParseErrors(t *testing.T) {
	fakeHome(t)
	tests := []struct{ name, cfg, lookup string }{
		{"unterminated quote", "Host a\n  HostName \"x\n", ""},
		{"missing value", "Host a\n  User\n", ""},
		{"bad port", "Host a\n  Port ssh\n", "a"},
		{"port out of range", "Host a\n  Port 70000\n", "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Parse(strings.NewReader(tt.cfg))
			if err == nil && tt.lookup != "" {
				_, err = c.Lookup(tt.lookup)
			}
			if err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestIncludeInsideHostKeepsSection(t *testing.T) {
	home := fakeHome(t)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "inc"), []byte("User scoped\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Parse(strings.NewReader("Host a\n  Include inc\n  Port 2022\nHost b\n  HostName b.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := c.Lookup("a")
	b, _ := c.Lookup("b")
	if a.User != "scoped" || a.Port != 2022 {
		t.Errorf("a = %+v", a)
	}
	if b.User != "" {
		t.Errorf("include leaked out of Host a: b = %+v", b)
	}
}

func TestMissingFileIsEmpty(t *testing.T) {
	fakeHome(t)
	c, err := Load(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Aliases()) != 0 {
		t.Errorf("Aliases = %v", c.Aliases())
	}
}

func TestWildcard(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"web-?", "web-1", true},
		{"web-?", "web-10", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", false},
		{"WEB-*", "web-1", true},
		{"a*b*c", "aXXbYc", true},
		{"a*b*c", "aXXbY", false},
	}
	for _, tt := range tests {
		if got := wildcard(tt.pattern, tt.s); got != tt.want {
			t.Errorf("wildcard(%q, %q) = %v; want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

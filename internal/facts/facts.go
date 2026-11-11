// Package facts gathers basic, read-only information about a target host.
// Phase 0 collects just enough for `vio hosts check`; see specs/plan.md §5.6.
package facts

import (
	"bufio"
	"context"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/transport"
)

// Basic is the minimum we learn about a host on connect.
type Basic struct {
	OS     string // PRETTY_NAME from /etc/os-release, e.g. "Ubuntu 24.04.1 LTS"
	Kernel string
	Arch   string
	User   string
	Root   bool // logged in as uid 0
	Sudo   bool // passwordless sudo available
}

// GatherBasic runs a few read-only commands. Fields it cannot determine stay empty.
func GatherBasic(ctx context.Context, x transport.Executor) (Basic, error) {
	var b Basic
	res, err := x.Run(ctx, transport.Cmd{Args: []string{"uname", "-rm"}})
	if err != nil {
		return b, err
	}
	if f := strings.Fields(string(res.Stdout)); len(f) == 2 {
		b.Kernel, b.Arch = f[0], f[1]
	}

	if res, err := x.Run(ctx, transport.Cmd{Args: []string{"id", "-un"}}); err == nil {
		b.User = strings.TrimSpace(string(res.Stdout))
	}
	if res, err := x.Run(ctx, transport.Cmd{Args: []string{"id", "-u"}}); err == nil {
		b.Root = strings.TrimSpace(string(res.Stdout)) == "0"
	}
	if b.Root {
		b.Sudo = true
	} else if res, err := x.Run(ctx, transport.Cmd{Args: []string{"true"}, Sudo: true}); err == nil {
		b.Sudo = res.ExitCode == 0
	}

	if data, _, err := x.ReadFile(ctx, "/etc/os-release", 64*1024); err == nil {
		b.OS = ParseOSRelease(string(data))["PRETTY_NAME"]
	}
	return b, nil
}

// ParseOSRelease parses the KEY=value format of /etc/os-release.
func ParseOSRelease(s string) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

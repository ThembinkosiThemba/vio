package agent

import (
	"fmt"
	"slices"
	"strings"
)

// The agent may only run commands that cannot change the host. Each entry checks
// argv (never a shell string) and rejects flags or subcommands that write, follow
// forever, or execute other programs. Anything else waits for the plan/apply
// engine (specs/plan.md §5.10).

type argCheck func(args []string) error

func anyArgs(_ []string) error { return nil }

func denyFlags(flags ...string) argCheck {
	return func(args []string) error {
		for _, a := range args {
			for _, f := range flags {
				if a == f || strings.HasPrefix(a, f+"=") || (strings.HasPrefix(f, "--") && strings.HasPrefix(a, f)) {
					return fmt.Errorf("flag %s is not allowed", a)
				}
			}
		}
		return nil
	}
}

// firstWord requires the first non-flag argument to be one of verbs (or absent if allowEmpty).
func firstWord(allowEmpty bool, verbs ...string) argCheck {
	return func(args []string) error {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				continue
			}
			if slices.Contains(verbs, a) {
				return nil
			}
			return fmt.Errorf("subcommand %q is not allowed (allowed: %s)", a, strings.Join(verbs, ", "))
		}
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("a subcommand is required (allowed: %s)", strings.Join(verbs, ", "))
	}
}

func onlyFlags(allowed ...string) argCheck {
	return func(args []string) error {
		for _, a := range args {
			if !slices.Contains(allowed, a) {
				return fmt.Errorf("argument %q is not allowed (allowed: %s)", a, strings.Join(allowed, " "))
			}
		}
		return nil
	}
}

func all(checks ...argCheck) argCheck {
	return func(args []string) error {
		for _, c := range checks {
			if err := c(args); err != nil {
				return err
			}
		}
		return nil
	}
}

var followFlags = denyFlags("-f", "-F", "--follow", "--retry")

var allowlist = map[string]argCheck{
	// system
	"uname": anyArgs, "uptime": anyArgs, "hostname": onlyFlags("-f", "-I", "-i", "-s", "-d"),
	"whoami": anyArgs, "id": anyArgs, "date": denyFlags("-s", "--set"), "nproc": anyArgs,
	"lscpu": anyArgs, "lsblk": anyArgs, "free": anyArgs, "df": anyArgs, "du": anyArgs,
	"vmstat": anyArgs, "iostat": anyArgs, "w": anyArgs, "who": anyArgs, "users": anyArgs,
	"last": anyArgs, "lastlog": anyArgs, "lastb": anyArgs, "getent": anyArgs,
	"ps": anyArgs, "pgrep": anyArgs, "locale": anyArgs,
	"top":         func(a []string) error { return requireAll(a, "-b", "-n") },
	"timedatectl": firstWord(true, "status", "show", "show-timesync", "timesync-status"),
	"hostnamectl": firstWord(true, "status"),
	"loginctl":    firstWord(true, "list-sessions", "list-users", "show-session", "show-user", "session-status", "user-status"),

	// files (read-only tools)
	"ls": anyArgs, "stat": anyArgs, "file": anyArgs, "wc": anyArgs, "cat": anyArgs,
	"head": anyArgs, "tail": followFlags, "grep": anyArgs, "zgrep": anyArgs, "readlink": anyArgs,
	"sha256sum": anyArgs, "md5sum": anyArgs,
	"find": denyFlags("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"),

	// network
	"ss": anyArgs, "netstat": anyArgs,
	"ip":  ipCheck,
	"dig": anyArgs, "host": anyArgs, "nslookup": anyArgs, "resolvectl": firstWord(true, "status", "dns", "domain", "statistics", "query"),
	"ping": func(a []string) error { return requireAll(a, "-c") },

	// services and logs
	"systemctl": all(firstWord(true, "status", "show", "cat", "list-units", "list-unit-files", "list-timers",
		"list-sockets", "list-dependencies", "is-active", "is-enabled", "is-failed", "is-system-running", "--failed"),
		denyFlags("--now")),
	"journalctl": denyFlags("-f", "--follow", "--vacuum-size", "--vacuum-time", "--vacuum-files",
		"--rotate", "--flush", "--sync", "--relinquish-var", "--smart-relinquish-var", "--setup-keys", "--update-catalog"),
	"service": func(a []string) error {
		if len(a) == 1 && a[0] == "--status-all" || len(a) == 2 && a[1] == "status" {
			return nil
		}
		return fmt.Errorf("only `service --status-all` or `service <name> status` are allowed")
	},

	// packages
	"apt":        firstWord(false, "list", "policy", "show", "search"),
	"apt-cache":  firstWord(false, "policy", "show", "search", "depends", "rdepends", "showpkg"),
	"dpkg":       onlyFirstFlag("-l", "--list", "-L", "--listfiles", "-s", "--status", "-S", "--search", "--print-architecture", "--audit", "-C"),
	"dpkg-query": anyArgs,
	"rpm":        onlyFirstFlag("-q", "-qa", "-qi", "-ql", "-qf", "--query"),
	"dnf":        firstWord(false, "list", "info", "check-update", "repolist", "updateinfo", "search"),
	"yum":        firstWord(false, "list", "info", "check-update", "repolist", "updateinfo", "search"),
	"apk":        firstWord(false, "info", "list", "search", "version", "policy"),
	"snap":       firstWord(false, "list", "info", "services"),

	// security
	"sshd":            func(a []string) error { return onlyFlags("-T")(a) },
	"ufw":             firstWord(false, "status"),
	"iptables":        onlyFirstFlag("-S", "-L", "--list", "--list-rules"),
	"ip6tables":       onlyFirstFlag("-S", "-L", "--list", "--list-rules"),
	"iptables-save":   anyArgs,
	"nft":             firstWord(false, "list"),
	"firewall-cmd":    onlyFirstFlag("--state", "--list-all", "--list-all-zones", "--list-ports", "--list-services", "--get-active-zones", "--get-default-zone"),
	"fail2ban-client": firstWord(false, "status", "ping", "version"),
	"crontab":         onlyFlags("-l"),
	"getenforce":      anyArgs, "sestatus": anyArgs, "aa-status": anyArgs,

	// web servers and containers
	"nginx":      onlyFlags("-t", "-T", "-v", "-V", "-q"),
	"apache2ctl": firstWord(false, "-t", "-S", "-M", "-V", "configtest"),
	"caddy":      firstWord(false, "version", "validate", "list-modules", "fmt"),
	"certbot":    firstWord(false, "certificates"),
	"docker":     dockerCheck,
}

// requireAll needs every flag in want to be present (e.g. top -b -n 1).
func requireAll(args []string, want ...string) error {
	for _, w := range want {
		found := false
		for _, a := range args {
			if a == w || strings.HasPrefix(a, w) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("must include %s", strings.Join(want, " "))
		}
	}
	return nil
}

// onlyFirstFlag requires the first argument to be one of the given query flags.
func onlyFirstFlag(flags ...string) argCheck {
	return func(args []string) error {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				if slices.Contains(flags, a) {
					return nil
				}
				// Allow benign modifiers before the action (-n, -v, -t table).
				if slices.Contains([]string{"-n", "-v", "-t", "--line-numbers", "-x", "--numeric", "--verbose"}, a) {
					continue
				}
				return fmt.Errorf("flag %s is not allowed (allowed: %s)", a, strings.Join(flags, " "))
			}
		}
		return fmt.Errorf("one of %s is required", strings.Join(flags, " "))
	}
}

func ipCheck(args []string) error {
	var words []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			words = append(words, a)
		}
	}
	if len(words) == 0 {
		return fmt.Errorf("an object is required (addr, route, link, neigh, rule)")
	}
	if !slices.Contains([]string{"a", "addr", "address", "r", "route", "l", "link", "n", "neigh", "neighbor", "rule", "-br"}, words[0]) {
		return fmt.Errorf("ip object %q is not allowed", words[0])
	}
	if len(words) > 1 && !slices.Contains([]string{"show", "list", "ls", "get"}, words[1]) {
		return fmt.Errorf("ip %s %s is not allowed (read-only: show, list, get)", words[0], words[1])
	}
	return nil
}

func dockerCheck(args []string) error {
	var words []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			words = append(words, a)
		}
	}
	if len(words) == 0 {
		return fmt.Errorf("a docker subcommand is required")
	}
	switch words[0] {
	case "ps", "images", "inspect", "version", "info", "top", "port", "diff", "history":
		return nil
	case "logs":
		return followFlags(args)
	case "stats":
		if !slices.Contains(args, "--no-stream") {
			return fmt.Errorf("docker stats needs --no-stream")
		}
		return nil
	case "network", "volume", "image", "container", "system", "compose":
		if len(words) > 1 && slices.Contains([]string{"ls", "list", "inspect", "ps", "df", "config", "images", "top"}, words[1]) {
			return nil
		}
		return fmt.Errorf("docker %s: only read-only subcommands (ls, inspect, ps, df) are allowed", words[0])
	}
	return fmt.Errorf("docker %s is not allowed", words[0])
}

// CheckCommand reports whether argv is an allowed read-only command.
func CheckCommand(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty command")
	}
	for _, a := range argv {
		if strings.ContainsAny(a, "\x00\n\r") {
			return fmt.Errorf("arguments may not contain control characters")
		}
	}
	name := argv[0]
	if strings.Contains(name, "/") {
		return fmt.Errorf("use the bare command name, not a path (%q)", name)
	}
	check, ok := allowlist[name]
	if !ok {
		return fmt.Errorf("%q is not on the read-only allowlist; changes need the plan/apply flow, which isn't available yet", name)
	}
	if err := check(argv[1:]); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// AllowedCommands lists allowlisted command names, for the tool description.
func AllowedCommands() []string {
	names := make([]string, 0, len(allowlist))
	for n := range allowlist {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// withDefaults adds flags that keep read-only commands non-interactive.
func withDefaults(argv []string) []string {
	switch argv[0] {
	case "systemctl", "journalctl":
		if !slices.Contains(argv, "--no-pager") {
			argv = append(argv[:1:1], append([]string{"--no-pager"}, argv[1:]...)...)
		}
	}
	return argv
}

// Package adapters hides distro differences behind small interfaces: package
// managers (apt, dnf, apk), init systems (systemd, openrc) and firewalls (ufw,
// firewalld). Adapters only build argv; they never run anything.
package adapters

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/facts"
)

// Pkg builds package manager commands.
type Pkg interface {
	Name() string
	// Refresh updates package indexes, or returns nil.
	Refresh() []string
	Install(pkgs ...string) []string
	Remove(pkgs ...string) []string
	// InstallExact installs specific versions (used to roll back upgrades).
	InstallExact(versions map[string]string) []string
	// Query prints one "name<TAB>version" line per installed package among pkgs.
	Query(pkgs ...string) []string
	// Upgradable lists pending upgrades; ParseUpgradable reads its output.
	Upgradable(security bool) []string
	ParseUpgradable(out string) []Upgrade
	// Upgrade upgrades exactly pkgs.
	Upgrade(pkgs ...string) []string
}

// Upgrade is one pending package upgrade.
type Upgrade struct {
	Name, To string
}

// PkgFor picks the package manager adapter for a host.
func PkgFor(f facts.Facts) (Pkg, error) {
	switch f.PkgMgr {
	case "apt":
		return apt{}, nil
	case "dnf", "yum":
		return dnf{bin: f.PkgMgr}, nil
	case "apk":
		return apk{}, nil
	}
	return nil, fmt.Errorf("no supported package manager found (apt, dnf, yum, apk)")
}

var aptEnv = []string{"env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a"}

type apt struct{}

func (apt) Name() string      { return "apt" }
func (apt) Refresh() []string { return join(aptEnv, "apt-get", "update", "-q") }
func (apt) Install(p ...string) []string {
	return join(aptEnv, append([]string{"apt-get", "install", "-y", "-q", "--no-install-recommends", "--"}, p...)...)
}
func (apt) Remove(p ...string) []string {
	return join(aptEnv, append([]string{"apt-get", "remove", "-y", "-q", "--"}, p...)...)
}
func (apt) InstallExact(v map[string]string) []string {
	args := []string{"apt-get", "install", "-y", "-q", "--allow-downgrades", "--"}
	for _, n := range sortedKeys(v) {
		args = append(args, n+"="+v[n])
	}
	return join(aptEnv, args...)
}
func (apt) Query(p ...string) []string {
	return append([]string{"dpkg-query", "-W", "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n", "--"}, p...)
}
func (apt) Upgradable(bool) []string { return []string{"apt", "list", "--upgradable", "-q"} }

// ParseUpgradable reads `apt list --upgradable` lines:
// "openssl/noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]".
// It returns all upgrades; security-only filtering uses the suite name.
func (apt) ParseUpgradable(out string) []Upgrade {
	var ups []Upgrade
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.Contains(f[0], "/") {
			continue
		}
		name, _, _ := strings.Cut(f[0], "/")
		ups = append(ups, Upgrade{Name: name, To: f[1]})
	}
	return ups
}

// AptSecurity reports whether an `apt list` line comes from a security suite.
func AptSecurity(line string) bool {
	f := strings.Fields(line)
	return len(f) > 0 && strings.Contains(f[0], "-security")
}

func (apt) Upgrade(p ...string) []string {
	return join(aptEnv, append([]string{"apt-get", "install", "-y", "-q", "--only-upgrade",
		"-o", "Dpkg::Options::=--force-confold", "--"}, p...)...)
}

type dnf struct{ bin string }

func (d dnf) Name() string      { return d.bin }
func (d dnf) Refresh() []string { return nil }
func (d dnf) Install(p ...string) []string {
	return append([]string{d.bin, "install", "-y", "-q", "--"}, p...)
}
func (d dnf) Remove(p ...string) []string {
	return append([]string{d.bin, "remove", "-y", "-q", "--"}, p...)
}
func (d dnf) InstallExact(v map[string]string) []string {
	args := []string{d.bin, "install", "-y", "-q", "--allowerasing", "--"}
	for _, n := range sortedKeys(v) {
		args = append(args, n+"-"+v[n])
	}
	return args
}
func (dnf) Query(p ...string) []string {
	return append([]string{"rpm", "-q", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\tii\n", "--"}, p...)
}
func (d dnf) Upgradable(security bool) []string {
	if security {
		return []string{d.bin, "-q", "check-update", "--security"}
	}
	return []string{d.bin, "-q", "check-update"}
}

// ParseUpgradable reads `dnf check-update` lines: "openssl.x86_64  1:3.0.7-27.el9  baseos".
func (dnf) ParseUpgradable(out string) []Upgrade {
	var ups []Upgrade
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || strings.HasPrefix(line, " ") || !strings.Contains(f[0], ".") {
			continue
		}
		name := f[0][:strings.LastIndex(f[0], ".")]
		ups = append(ups, Upgrade{Name: name, To: f[1]})
	}
	return ups
}
func (d dnf) Upgrade(p ...string) []string {
	return append([]string{d.bin, "upgrade", "-y", "-q", "--"}, p...)
}

type apk struct{}

func (apk) Name() string                 { return "apk" }
func (apk) Refresh() []string            { return []string{"apk", "update", "-q"} }
func (apk) Install(p ...string) []string { return append([]string{"apk", "add", "-q", "--"}, p...) }
func (apk) Remove(p ...string) []string  { return append([]string{"apk", "del", "-q", "--"}, p...) }
func (apk) InstallExact(v map[string]string) []string {
	args := []string{"apk", "add", "-q", "--"}
	for _, n := range sortedKeys(v) {
		args = append(args, n+"="+v[n])
	}
	return args
}

// Query uses a fixed script: apk has no format flag, so we print "name\tversion\tii".
func (apk) Query(p ...string) []string {
	const script = `for p in "$@"; do v=$(apk info -e -v "$p" 2>/dev/null | sed "s/^$p-//"); [ -n "$v" ] && printf '%s\t%s\tii\n' "$p" "$v"; done; true`
	return append([]string{"sh", "-c", script, "sh"}, p...)
}
func (apk) Upgradable(bool) []string { return []string{"apk", "version", "-l", "<"} }

// ParseUpgradable reads `apk version -l '<'` lines: "openssl-3.1.4-r0  < 3.1.4-r5".
func (apk) ParseUpgradable(out string) []Upgrade {
	var ups []Upgrade
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[1] != "<" {
			continue
		}
		// Strip "-<version>-r<n>" from the installed name-version.
		nv := f[0]
		i := strings.LastIndex(nv, "-r")
		if i > 0 {
			nv = nv[:i]
		}
		if j := strings.LastIndex(nv, "-"); j > 0 {
			nv = nv[:j]
		}
		ups = append(ups, Upgrade{Name: nv, To: f[2]})
	}
	return ups
}
func (apk) Upgrade(p ...string) []string {
	return append([]string{"apk", "add", "-q", "-u", "--"}, p...)
}

// ParseQuery reads Query output into name → version for installed packages.
func ParseQuery(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 3 && strings.HasPrefix(f[2], "ii") {
			m[f[0]] = f[1]
		}
	}
	return m
}

// Svc builds service manager commands.
type Svc interface {
	Name() string
	// Action returns argv for start|stop|restart|reload|enable|disable.
	Action(action, unit string) ([]string, error)
	// State prints "<active|inactive> <enabled|disabled>" for unit.
	State(unit string) []string
	DaemonReload() []string // nil if not needed
}

// SvcFor picks the init system adapter.
func SvcFor(f facts.Facts) (Svc, error) {
	switch f.Init {
	case "systemd":
		return systemd{}, nil
	case "openrc":
		return openrc{}, nil
	}
	return nil, fmt.Errorf("no supported init system found (systemd, openrc)")
}

// Inverse maps a service action to the one that undoes it, given the prior state.
func Inverse(action string, wasActive, wasEnabled bool) string {
	switch action {
	case "start", "stop", "restart", "reload":
		if wasActive {
			return "start"
		}
		return "stop"
	case "enable", "disable":
		if wasEnabled {
			return "enable"
		}
		return "disable"
	}
	return ""
}

type systemd struct{}

func (systemd) Name() string { return "systemd" }
func (systemd) Action(action, unit string) ([]string, error) {
	switch action {
	case "start", "stop", "restart", "reload", "enable", "disable":
		return []string{"systemctl", action, "--", unit}, nil
	}
	return nil, fmt.Errorf("unknown service action %q", action)
}

const systemdState = `a=$(systemctl is-active -- "$1" 2>/dev/null); e=$(systemctl is-enabled -- "$1" 2>/dev/null)
[ "$a" = active ] || a=inactive; case "$e" in enabled|enabled-runtime|alias|static|indirect) e=enabled;; *) e=disabled;; esac
echo "$a $e"`

func (systemd) State(unit string) []string { return []string{"sh", "-c", systemdState, "sh", unit} }
func (systemd) DaemonReload() []string     { return []string{"systemctl", "daemon-reload"} }

type openrc struct{}

func (openrc) Name() string { return "openrc" }
func (openrc) Action(action, unit string) ([]string, error) {
	switch action {
	case "start", "stop", "restart", "reload":
		return []string{"rc-service", unit, action}, nil
	case "enable":
		return []string{"rc-update", "add", unit, "default"}, nil
	case "disable":
		return []string{"rc-update", "del", unit, "default"}, nil
	}
	return nil, fmt.Errorf("unknown service action %q", action)
}

const openrcState = `if rc-service "$1" status >/dev/null 2>&1; then a=active; else a=inactive; fi
if rc-update show default 2>/dev/null | grep -qw -- "$1"; then e=enabled; else e=disabled; fi
echo "$a $e"`

func (openrc) State(unit string) []string { return []string{"sh", "-c", openrcState, "sh", unit} }
func (openrc) DaemonReload() []string     { return nil }

// Rule is a firewall rule in vio's terms.
type Rule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto,omitempty"` // tcp | udp; default tcp
	From  string `json:"from,omitempty"`  // source CIDR; default any
}

func (r Rule) proto() string {
	if r.Proto == "" {
		return "tcp"
	}
	return r.Proto
}

// String renders the rule as "22/tcp from 10.0.0.0/8".
func (r Rule) String() string {
	s := fmt.Sprintf("%d/%s", r.Port, r.proto())
	if r.From != "" && r.From != "any" {
		s += " from " + r.From
	}
	return s
}

// FW builds firewall commands. Each method returns steps (argv lists) and the
// commands that undo them.
type FW interface {
	Name() string
	Rule(verb string, r Rule) (do, undo [][]string, err error) // verb: allow | deny
	Enable() (do, undo [][]string)
	DefaultDenyIncoming(prevPolicy string) (do, undo [][]string, err error)
	// Rules prints the configured rules even while the firewall is inactive.
	Rules() []string
	// Allows reports whether Rules output allows inbound port/tcp from anywhere.
	Allows(rulesOut string, port int) bool
}

// FWFor picks the firewall adapter.
func FWFor(f facts.Facts) (FW, error) {
	switch f.Firewall {
	case "ufw":
		return ufw{}, nil
	case "firewalld":
		return firewalld{}, nil
	}
	return nil, fmt.Errorf("firewall %q is not supported for changes yet (ufw and firewalld are)", f.Firewall)
}

type ufw struct{}

func (ufw) Name() string { return "ufw" }
func (ufw) Rule(verb string, r Rule) ([][]string, [][]string, error) {
	if verb != "allow" && verb != "deny" {
		return nil, nil, fmt.Errorf("unknown verb %q", verb)
	}
	from := r.From
	if from == "" {
		from = "any"
	}
	spec := []string{"proto", r.proto(), "from", from, "to", "any", "port", fmt.Sprint(r.Port)}
	return [][]string{append([]string{"ufw", verb}, spec...)},
		[][]string{append([]string{"ufw", "delete", verb}, spec...)}, nil
}
func (ufw) Enable() ([][]string, [][]string) {
	return [][]string{{"ufw", "--force", "enable"}}, [][]string{{"ufw", "disable"}}
}
func (ufw) DefaultDenyIncoming(prev string) ([][]string, [][]string, error) {
	if prev == "" {
		prev = "allow"
	}
	return [][]string{{"ufw", "default", "deny", "incoming"}}, [][]string{{"ufw", "default", prev, "incoming"}}, nil
}
func (ufw) Rules() []string { return []string{"ufw", "show", "added"} }

// Allows looks for "ufw allow 22", "ufw allow 22/tcp", "ufw allow OpenSSH" and
// the long form vio writes.
func (ufw) Allows(out string, port int) bool {
	p := fmt.Sprint(port)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "ufw" || f[1] != "allow" || strings.Contains(line, " from ") && !strings.Contains(line, "from any") {
			continue
		}
		last := f[len(f)-1]
		if last == p || last == p+"/tcp" || f[2] == p || f[2] == p+"/tcp" || port == 22 && (f[2] == "OpenSSH" || f[2] == "ssh") {
			return true
		}
	}
	return false
}

type firewalld struct{}

func (firewalld) Name() string { return "firewalld" }
func (firewalld) Rule(verb string, r Rule) ([][]string, [][]string, error) {
	var add, rm string
	switch {
	case verb == "allow" && (r.From == "" || r.From == "any"):
		add = fmt.Sprintf("--add-port=%d/%s", r.Port, r.proto())
		rm = "--remove" + add[len("--add"):]
	case verb == "allow" || verb == "deny":
		from := r.From
		if from == "" || from == "any" {
			from = "0.0.0.0/0"
		}
		act := "accept"
		if verb == "deny" {
			act = "reject"
		}
		rule := fmt.Sprintf(`rule family="ipv4" source address="%s" port port="%d" protocol="%s" %s`, from, r.Port, r.proto(), act)
		add, rm = "--add-rich-rule="+rule, "--remove-rich-rule="+rule
	default:
		return nil, nil, fmt.Errorf("unknown verb %q", verb)
	}
	reload := []string{"firewall-cmd", "--reload"}
	return [][]string{{"firewall-cmd", "--permanent", add}, reload},
		[][]string{{"firewall-cmd", "--permanent", rm}, reload}, nil
}
func (firewalld) Enable() ([][]string, [][]string) {
	return [][]string{{"systemctl", "enable", "--now", "firewalld"}}, [][]string{{"systemctl", "disable", "--now", "firewalld"}}
}
func (firewalld) DefaultDenyIncoming(string) ([][]string, [][]string, error) {
	return nil, nil, fmt.Errorf("firewalld zones already deny unlisted inbound traffic; use fw_allow and fw_deny")
}
func (firewalld) Rules() []string {
	return []string{"sh", "-c", `firewall-cmd --permanent --list-all 2>/dev/null || firewall-offline-cmd --list-all 2>/dev/null; true`}
}
func (firewalld) Allows(out string, port int) bool {
	p := fmt.Sprintf("%d/tcp", port)
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		switch k {
		case "ports":
			for _, x := range f {
				if x == p {
					return true
				}
			}
		case "services":
			for _, x := range f {
				if x == "ssh" && port == 22 {
					return true
				}
			}
		}
	}
	return false
}

func join(prefix []string, rest ...string) []string {
	return append(append([]string{}, prefix...), rest...)
}

func sortedKeys(m map[string]string) []string { return slices.Sorted(maps.Keys(m)) }

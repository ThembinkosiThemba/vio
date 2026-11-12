// Package observe holds vio's read-only tools. None of them may change host
// state; anything that can belongs in package change.
package observe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/redact"
	"github.com/ThembinkosiThemba/vio/internal/tools"
	"github.com/ThembinkosiThemba/vio/internal/tools/adapters"
)

// All returns every observe tool.
func All() []tools.Tool {
	return []tools.Tool{
		runCommand{}, readFile{}, hostFacts{},
		fsList, fsStat, fsGrep, procList, netListeners, netConnections,
		fwStatus, svcStatus, svcList, logJournal, logTail,
		pkgQuery, pkgUpdates, userList, sshdEffective, diskUsage, tlsCert,
	}
}

// cmdTool is an observe tool that runs one argv built from its arguments.
type cmdTool struct {
	name, desc, schema string
	sudo               bool // run as root when the host allows it
	build              func(h *tools.Host, raw json.RawMessage) ([]string, error)
}

func (t cmdTool) Name() string            { return t.name }
func (t cmdTool) Description() string     { return t.desc }
func (t cmdTool) Schema() json.RawMessage { return json.RawMessage(t.schema) }
func (t cmdTool) Tier() plan.Tier         { return plan.Observe }

func (t cmdTool) Observe(ctx context.Context, h *tools.Host, raw json.RawMessage) (tools.Output, error) {
	argv, err := t.build(h, raw)
	if err != nil {
		return tools.Output{}, err
	}
	sudo := t.sudo && (h.Facts.Sudo || h.Facts.Root)
	res, err := h.Run(ctx, sudo, argv...)
	label := strings.Join(argv, " ")
	if argv[0] == "sh" {
		label = t.name // fixed scripts are long; the tool name says what ran
	}
	if err != nil {
		return tools.Output{Label: label, Exit: -1}, err
	}
	return tools.Output{Label: label, Text: combine(res.Stdout, res.Stderr), Exit: res.ExitCode, Truncated: res.Truncated}, nil
}

func combine(stdout, stderr []byte) string {
	var b strings.Builder
	b.Write(stdout)
	if len(stderr) > 0 {
		b.WriteString("\n[stderr]\n")
		b.Write(stderr)
	}
	return b.String()
}

const noArgs = `{"type":"object","properties":{}}`

// absPath validates a path argument.
func absPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path must be absolute, got %q", p)
	}
	if strings.ContainsAny(p, "\x00\n\r") {
		return errors.New("path may not contain control characters")
	}
	if bad, why := redact.Forbidden(p); bad {
		return fmt.Errorf("%s holds %s and is never read into the conversation", p, why)
	}
	return nil
}

// name validates a unit, package, or user name argument.
func name(kind, s string) error {
	if s == "" || strings.HasPrefix(s, "-") || strings.ContainsAny(s, " \t\x00\n\r/") {
		return fmt.Errorf("invalid %s %q", kind, s)
	}
	return nil
}

func clamp(n, def, hi int) int {
	if n <= 0 {
		return def
	}
	return min(n, hi)
}

var fsList = cmdTool{
	name: "fs_list", desc: "List a directory with sizes, owners, permissions and modification times.",
	schema: `{"type":"object","properties":{"path":{"type":"string","description":"Absolute directory path"}},"required":["path"]}`,
	sudo:   true,
	build: func(_ *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct{ Path string }
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		if err := absPath(in.Path); err != nil {
			return nil, err
		}
		return []string{"ls", "-la", "--time-style=long-iso", "--", in.Path}, nil
	},
}

var fsStat = cmdTool{
	name: "fs_stat", desc: "Show a file's type, size, mode, owner and timestamps.",
	schema: `{"type":"object","properties":{"path":{"type":"string","description":"Absolute path"}},"required":["path"]}`,
	sudo:   true,
	build: func(_ *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct{ Path string }
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		if err := absPath(in.Path); err != nil {
			return nil, err
		}
		return []string{"stat", "--", in.Path}, nil
	},
}

var fsGrep = cmdTool{
	name: "fs_grep", desc: "Search files for a regular expression (grep -E). Prints matching lines with line numbers.",
	schema: `{"type":"object","properties":{
		"pattern":{"type":"string","description":"Extended regular expression"},
		"path":{"type":"string","description":"Absolute file or directory path"},
		"recursive":{"type":"boolean"},
		"ignore_case":{"type":"boolean"},
		"max_matches":{"type":"integer","description":"Per file, default 50"}},
		"required":["pattern","path"]}`,
	sudo: true,
	build: func(_ *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct {
			Pattern    string
			Path       string
			Recursive  bool
			IgnoreCase bool `json:"ignore_case"`
			MaxMatches int  `json:"max_matches"`
		}
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		if err := absPath(in.Path); err != nil {
			return nil, err
		}
		argv := []string{"grep", "-n", "-I", "-E", "-m", strconv.Itoa(clamp(in.MaxMatches, 50, 500))}
		if in.Recursive {
			argv = append(argv, "-r")
		}
		if in.IgnoreCase {
			argv = append(argv, "-i")
		}
		return append(argv, "-e", in.Pattern, "--", in.Path), nil
	},
}

var procList = cmdTool{
	name: "proc_list", desc: "List processes sorted by CPU or memory use.",
	schema: `{"type":"object","properties":{"sort":{"type":"string","enum":["cpu","mem"]}}}`,
	build: func(_ *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct{ Sort string }
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		key := "-%cpu"
		if in.Sort == "mem" {
			key = "-%mem"
		}
		return []string{"ps", "-eo", "pid,ppid,user,%cpu,%mem,rss,etime,stat,args", "--sort=" + key, "--cols", "200"}, nil
	},
}

var netListeners = cmdTool{
	name: "net_listeners", desc: "List listening TCP and UDP sockets with their processes (ss -tulpn).",
	schema: noArgs, sudo: true,
	build: func(*tools.Host, json.RawMessage) ([]string, error) { return []string{"ss", "-tulpn"}, nil },
}

var netConnections = cmdTool{
	name: "net_connections", desc: "List established TCP connections with their processes.",
	schema: noArgs, sudo: true,
	build: func(*tools.Host, json.RawMessage) ([]string, error) {
		return []string{"ss", "-tnp", "state", "established"}, nil
	},
}

var fwStatus = cmdTool{
	name: "fw_status", desc: "Show the firewall's state and rules (ufw, firewalld, nftables or iptables, whichever the host uses).",
	schema: noArgs, sudo: true,
	build: func(h *tools.Host, _ json.RawMessage) ([]string, error) {
		switch h.Facts.Firewall {
		case "ufw":
			return []string{"sh", "-c", "ufw status verbose; echo; echo '# rules configured (shown even when inactive):'; ufw show added"}, nil
		case "firewalld":
			return []string{"sh", "-c", "firewall-cmd --state; firewall-cmd --list-all"}, nil
		case "nftables":
			return []string{"nft", "list", "ruleset"}, nil
		case "iptables":
			return []string{"iptables", "-S"}, nil
		}
		return []string{"sh", "-c", "echo 'no firewall found (ufw, firewalld, nft, iptables)'"}, nil
	},
}

var svcStatus = cmdTool{
	name: "svc_status", desc: "Show a service's status and its most recent log lines.",
	schema: `{"type":"object","properties":{"name":{"type":"string","description":"Service name, e.g. nginx"}},"required":["name"]}`,
	sudo:   true,
	build: func(h *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct{ Name string }
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		if err := name("service", in.Name); err != nil {
			return nil, err
		}
		if h.Facts.Init == "openrc" {
			return []string{"rc-service", in.Name, "status"}, nil
		}
		return []string{"systemctl", "status", "--no-pager", "-l", "-n", "30", "--", in.Name}, nil
	},
}

var svcList = cmdTool{
	name: "svc_list", desc: "List services and their states. Set failed to list only failed ones.",
	schema: `{"type":"object","properties":{"failed":{"type":"boolean"}}}`,
	build: func(h *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct{ Failed bool }
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		if h.Facts.Init == "openrc" {
			return []string{"rc-status", "-a"}, nil
		}
		argv := []string{"systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain"}
		if in.Failed {
			argv = append(argv, "--state=failed")
		}
		return argv, nil
	},
}

var logJournal = cmdTool{
	name: "log_journal", desc: "Read the systemd journal, optionally filtered by unit, time, priority or a pattern.",
	schema: `{"type":"object","properties":{
		"unit":{"type":"string","description":"e.g. nginx or ssh"},
		"since":{"type":"string","description":"e.g. '1 hour ago', 'today', '2026-11-12 09:00'"},
		"priority":{"type":"string","enum":["emerg","alert","crit","err","warning","notice","info","debug"]},
		"grep":{"type":"string","description":"Only lines matching this pattern"},
		"lines":{"type":"integer","description":"Default 200"}}}`,
	sudo: true,
	build: func(_ *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct {
			Unit, Since, Priority, Grep string
			Lines                       int
		}
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		argv := []string{"journalctl", "--no-pager", "-q", "-n", strconv.Itoa(clamp(in.Lines, 200, 2000))}
		if in.Unit != "" {
			if err := name("unit", in.Unit); err != nil {
				return nil, err
			}
			argv = append(argv, "-u", in.Unit)
		}
		if in.Since != "" {
			argv = append(argv, "--since="+in.Since)
		}
		if in.Priority != "" {
			argv = append(argv, "-p", in.Priority)
		}
		if in.Grep != "" {
			argv = append(argv, "--grep="+in.Grep)
		}
		return argv, nil
	},
}

var logTail = cmdTool{
	name: "log_tail", desc: "Show the last lines of a log file, e.g. /var/log/nginx/error.log.",
	schema: `{"type":"object","properties":{"path":{"type":"string"},"lines":{"type":"integer","description":"Default 200"}},"required":["path"]}`,
	sudo:   true,
	build: func(_ *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct {
			Path  string
			Lines int
		}
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		if err := absPath(in.Path); err != nil {
			return nil, err
		}
		return []string{"tail", "-n", strconv.Itoa(clamp(in.Lines, 200, 5000)), "--", in.Path}, nil
	},
}

var pkgQuery = cmdTool{
	name: "pkg_query", desc: "Show installed versions of packages. Missing packages are simply not listed.",
	schema: `{"type":"object","properties":{"names":{"type":"array","items":{"type":"string"}}},"required":["names"]}`,
	build: func(h *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct{ Names []string }
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		if len(in.Names) == 0 {
			return nil, errors.New("names is required")
		}
		for _, n := range in.Names {
			if err := name("package", n); err != nil {
				return nil, err
			}
		}
		pm, err := adapters.PkgFor(h.Facts)
		if err != nil {
			return nil, err
		}
		return pm.Query(in.Names...), nil
	},
}

var pkgUpdates = cmdTool{
	name: "pkg_updates", desc: "List pending package updates from the last index refresh. Set security for security updates only.",
	schema: `{"type":"object","properties":{"security":{"type":"boolean"}}}`,
	build: func(h *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct{ Security bool }
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		pm, err := adapters.PkgFor(h.Facts)
		if err != nil {
			return nil, err
		}
		if in.Security && pm.Name() == "apt" {
			return []string{"sh", "-c", "apt list --upgradable 2>/dev/null | grep -- -security || echo 'no security updates pending'"}, nil
		}
		return pm.Upgradable(in.Security), nil
	},
}

var userList = cmdTool{
	name: "user_list", desc: "List login-capable users (uid, home, shell) and members of admin groups (sudo, wheel, admin).",
	schema: noArgs,
	build: func(*tools.Host, json.RawMessage) ([]string, error) {
		const script = `echo '# users (name:uid:gid:home:shell)'
getent passwd | awk -F: '$3==0 || ($3>=1000 && $3<65534) || $7 !~ /(nologin|false)$/ {print $1":"$3":"$4":"$6":"$7}'
echo; echo '# admin groups'
for g in sudo wheel admin; do getent group "$g"; done; true`
		return []string{"sh", "-c", script}, nil
	},
}

var sshdEffective = cmdTool{
	name: "sshd_effective", desc: "Show the SSH server's effective configuration (sshd -T), after all includes and defaults.",
	schema: noArgs, sudo: true,
	build: func(*tools.Host, json.RawMessage) ([]string, error) { return []string{"sshd", "-T"}, nil },
}

var diskUsage = cmdTool{
	name: "disk_usage", desc: "Show filesystem usage, and with path, the largest entries directly under that directory.",
	schema: `{"type":"object","properties":{"path":{"type":"string","description":"Optional absolute directory to break down"}}}`,
	sudo:   true,
	build: func(_ *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct{ Path string }
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		if in.Path == "" {
			return []string{"df", "-hT", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay"}, nil
		}
		if err := absPath(in.Path); err != nil {
			return nil, err
		}
		const script = `df -h -- "$1"; echo; du -xh --max-depth=1 -- "$1" 2>/dev/null | sort -rh | head -n 25`
		return []string{"sh", "-c", script, "sh", in.Path}, nil
	},
}

var tlsCert = cmdTool{
	name: "tls_cert", desc: "Inspect the TLS certificate a local port serves: subject, issuer, validity dates and names.",
	schema: `{"type":"object","properties":{
		"port":{"type":"integer","description":"Default 443"},
		"servername":{"type":"string","description":"SNI name, e.g. app.example.com"}}}`,
	build: func(_ *tools.Host, raw json.RawMessage) ([]string, error) {
		var in struct {
			Port       int
			Servername string
		}
		if err := tools.Decode(raw, &in); err != nil {
			return nil, err
		}
		if in.Port == 0 {
			in.Port = 443
		}
		if in.Port < 1 || in.Port > 65535 {
			return nil, errors.New("port out of range")
		}
		if in.Servername != "" {
			if err := name("servername", in.Servername); err != nil {
				return nil, err
			}
		}
		const script = `command -v openssl >/dev/null || { echo 'openssl is not installed'; exit 1; }
sni=${2:+-servername "$2"}
echo | openssl s_client -connect "127.0.0.1:$1" $sni 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName`
		return []string{"sh", "-c", script, "sh", strconv.Itoa(in.Port), in.Servername}, nil
	},
}

// runCommand is the escape hatch for reading: any allowlisted read-only argv.
type runCommand struct{}

func (runCommand) Name() string { return "run_command" }
func (runCommand) Description() string {
	return "Run a read-only command and return its output. Pass the command as an array of arguments, without shell syntax " +
		"(no pipes, redirects, or $()). Only allowlisted read-only commands run; others are rejected with the reason. " +
		"Prefer the specific tools when one fits. Allowed: " + strings.Join(AllowedCommands(), ", ") + "."
}
func (runCommand) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{
		"command":{"type":"array","items":{"type":"string"},"description":"argv, e.g. [\"df\", \"-h\"]"},
		"sudo":{"type":"boolean","description":"Run with sudo (non-interactive). Use only when needed."}},
		"required":["command"]}`)
}
func (runCommand) Tier() plan.Tier { return plan.Observe }

func (runCommand) Observe(ctx context.Context, h *tools.Host, raw json.RawMessage) (tools.Output, error) {
	var in struct {
		Command json.RawMessage
		Sudo    bool
	}
	if err := tools.Decode(raw, &in); err != nil {
		return tools.Output{}, err
	}
	argv, err := ParseArgv(in.Command)
	if err != nil {
		return tools.Output{}, err
	}
	if err := CheckCommand(argv); err != nil {
		return tools.Output{}, err
	}
	argv = withDefaults(argv)
	label := strings.Join(argv, " ")
	if in.Sudo {
		label = "sudo " + label
	}
	res, err := h.Run(ctx, in.Sudo, argv...)
	if err != nil {
		return tools.Output{Label: label, Exit: -1}, err
	}
	text := combine(res.Stdout, res.Stderr)
	if in.Sudo && res.ExitCode == 1 && strings.Contains(string(res.Stderr), "sudo:") {
		text += "\n[vio] sudo needs a password or isn't allowed for this user, so this command can't run with sudo."
	}
	return tools.Output{Label: label, Text: text, Exit: res.ExitCode, Truncated: res.Truncated}, nil
}

// ParseArgv accepts an argv array, or a simple space-separated string from
// models that ignore the schema. Shell syntax is rejected rather than guessed at.
func ParseArgv(raw json.RawMessage) ([]string, error) {
	var argv []string
	if json.Unmarshal(raw, &argv) == nil {
		return argv, nil
	}
	var line string
	if err := json.Unmarshal(raw, &line); err != nil {
		return nil, errors.New("command must be an array of strings")
	}
	if strings.ContainsAny(line, "|;&<>`$()'\"\\*") {
		return nil, errors.New("shell syntax isn't supported; pass the command as an array of arguments, one command per call")
	}
	return strings.Fields(line), nil
}

type readFile struct{}

func (readFile) Name() string { return "read_file" }
func (readFile) Description() string {
	return "Read a text file. Secrets are masked. Password hashes and private keys can't be read."
}
func (readFile) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{
		"path":{"type":"string","description":"Absolute path, e.g. /etc/ssh/sshd_config"},
		"sudo":{"type":"boolean","description":"Read with sudo. Use only when needed."}},
		"required":["path"]}`)
}
func (readFile) Tier() plan.Tier { return plan.Observe }

// MaxRead bounds read_file.
const MaxRead = 512 * 1024

func (readFile) Observe(ctx context.Context, h *tools.Host, raw json.RawMessage) (tools.Output, error) {
	var in struct {
		Path string
		Sudo bool
	}
	if err := tools.Decode(raw, &in); err != nil {
		return tools.Output{}, err
	}
	if err := absPath(in.Path); err != nil {
		return tools.Output{}, err
	}
	label := "read " + in.Path
	x := h.X
	if in.Sudo {
		label = "sudo " + label
		x = h.Root()
	}
	data, info, err := x.ReadFile(ctx, in.Path, MaxRead)
	if err != nil {
		return tools.Output{Label: label, Exit: 1}, err
	}
	return tools.Output{Label: label, Text: string(data), Truncated: info.Size > MaxRead}, nil
}

type hostFacts struct{}

func (hostFacts) Name() string { return "host_facts" }
func (hostFacts) Description() string {
	return "Summarize the host: OS, kernel, init system, package manager, firewall, login user, sudo, SSH port, uptime, CPU, memory."
}
func (hostFacts) Schema() json.RawMessage { return json.RawMessage(noArgs) }
func (hostFacts) Tier() plan.Tier         { return plan.Observe }

func (hostFacts) Observe(ctx context.Context, h *tools.Host, _ json.RawMessage) (tools.Output, error) {
	f := h.Facts
	var b strings.Builder
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "%-16s %s\n", k+":", v)
		}
	}
	row("os", f.OS)
	row("kernel", f.Kernel+" "+f.Arch)
	row("virtualization", f.Virt)
	row("init", f.Init)
	row("package manager", f.PkgMgr)
	fw := f.Firewall
	if fw != "none" {
		fw += map[bool]string{true: " (active)", false: " (inactive)"}[f.FirewallActive]
	}
	row("firewall", fw)
	row("login user", f.User)
	row("root", strconv.FormatBool(f.Root))
	row("sudo", strconv.FormatBool(f.Sudo))
	if f.SSHPort != 0 {
		row("ssh port", strconv.Itoa(f.SSHPort)+" (this connection)")
	}
	row("ssh service", f.SSHUnit)
	row("operator ip", f.ClientIP)
	if res, err := h.Run(ctx, false, "sh", "-c", "uptime; nproc; free -h | sed -n 2p"); err == nil {
		lines := strings.Split(strings.TrimSpace(string(res.Stdout)), "\n")
		if len(lines) == 3 {
			row("uptime", strings.TrimSpace(lines[0]))
			row("cpus", lines[1])
			row("memory", strings.Join(strings.Fields(lines[2])[1:], " "))
		}
	}
	return tools.Output{Label: "host facts", Text: b.String()}, nil
}

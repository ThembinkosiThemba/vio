// Package checks is vio's deterministic security baseline. It runs without a
// model, so `vio check` works offline and in CI and gives the agent ground
// truth. Failing checks may carry a Fix: a change tool call that becomes a
// plan action. See specs/plan.md §5.14.
package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/tools"
)

// Severity of a finding.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"info", "low", "medium", "high", "critical"}[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Status of a finding.
const (
	Pass  = "pass"
	Fail  = "fail"
	Skip  = "skip"
	Error = "error"
)

// Fix is a change tool call that resolves a finding.
type Fix struct {
	Tool string          `json:"tool"`
	Args json.RawMessage `json:"args"`
}

// Finding is the result of one check on one host.
type Finding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail,omitempty"`
	Fix      *Fix     `json:"fix,omitempty"`
}

// Check is one baseline rule.
type Check struct {
	ID       string
	Title    string
	Severity Severity
	Run      func(ctx context.Context, h *tools.Host) Finding
}

func fix(tool string, args any) *Fix {
	b, _ := json.Marshal(args)
	return &Fix{Tool: tool, Args: b}
}

// Run runs every check against h, in order.
func Run(ctx context.Context, h *tools.Host) []Finding {
	var out []Finding
	sshd := sshdConfig(ctx, h)
	for _, c := range All(sshd) {
		f := c.Run(ctx, h)
		f.ID, f.Title = c.ID, c.Title
		if f.Status == Fail && f.Severity == Info {
			f.Severity = c.Severity
		}
		out = append(out, f)
	}
	return out
}

func pass(d string) Finding { return Finding{Status: Pass, Detail: d} }
func skip(d string) Finding { return Finding{Status: Skip, Detail: d} }
func failed(d string, fx *Fix) Finding {
	return Finding{Status: Fail, Detail: d, Fix: fx}
}
func errored(err error) Finding { return Finding{Status: Error, Detail: err.Error()} }

// sshdConfig reads `sshd -T` once; nil means unavailable.
func sshdConfig(ctx context.Context, h *tools.Host) map[string]string {
	if !h.Facts.Root && !h.Facts.Sudo {
		return nil
	}
	out, err := h.Output(ctx, "sshd", "-T")
	if err != nil {
		return nil
	}
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), " ")
		if ok {
			if _, dup := m[k]; !dup {
				m[k] = v
			}
		}
	}
	return m
}

func sshdCheck(sshd map[string]string, key string, good func(string) bool, want string, sev Severity) func(context.Context, *tools.Host) Finding {
	return func(_ context.Context, h *tools.Host) Finding {
		if sshd == nil {
			return skip("needs root or sudo to read `sshd -T`")
		}
		v := sshd[strings.ToLower(key)]
		if good(v) {
			return pass(key + " " + v)
		}
		if key == "PermitRootLogin" && h.Facts.Root {
			want = "prohibit-password"
		}
		f := failed(key+" "+v, fix("sshd_set", map[string]any{"settings": map[string]string{key: want}}))
		f.Severity = sev
		return f
	}
}

func is(vals ...string) func(string) bool {
	return func(v string) bool {
		for _, x := range vals {
			if v == x {
				return true
			}
		}
		return false
	}
}

// All returns the baseline, given `sshd -T` output (nil if unavailable).
func All(sshd map[string]string) []Check {
	return []Check{
		{"VIO-SSH-001", "SSH root login restricted", High,
			sshdCheck(sshd, "PermitRootLogin", is("no", "prohibit-password", "without-password", "forced-commands-only"), "no", High)},
		{"VIO-SSH-002", "SSH password authentication disabled", High,
			sshdCheck(sshd, "PasswordAuthentication", is("no"), "no", High)},
		{"VIO-SSH-003", "SSH empty passwords refused", Critical,
			sshdCheck(sshd, "PermitEmptyPasswords", is("no"), "no", Critical)},
		{"VIO-SSH-004", "SSH keyboard-interactive auth disabled", Medium,
			sshdCheck(sshd, "KbdInteractiveAuthentication", is("no", ""), "no", Medium)},
		{"VIO-SSH-005", "SSH X11 forwarding disabled", Low,
			sshdCheck(sshd, "X11Forwarding", is("no"), "no", Low)},
		{"VIO-SSH-006", "SSH MaxAuthTries at most 4", Low,
			sshdCheck(sshd, "MaxAuthTries", func(v string) bool { n, err := strconv.Atoi(v); return err == nil && n <= 4 }, "4", Low)},
		{"VIO-FW-001", "Firewall active", High, firewallActive},
		{"VIO-FW-002", "Firewall denies inbound by default", Medium, firewallDefaultDeny},
		{"VIO-NET-001", "Publicly exposed services", Info, publicListeners},
		{"VIO-PKG-001", "No pending security updates", Medium, securityUpdates},
		{"VIO-PKG-002", "Automatic security updates enabled", Medium, autoUpdates},
		{"VIO-SYS-001", "No reboot pending", Low, rebootRequired},
		{"VIO-AUTH-001", "Brute-force protection (fail2ban)", Medium, fail2ban(sshd)},
		{"VIO-USR-001", "Only root has uid 0", Critical, uidZero},
		{"VIO-USR-002", "No accounts with empty passwords", Critical, emptyPasswords},
		{"VIO-SUDO-001", "Passwordless sudo grants", Info, nopasswd},
		{"VIO-FS-001", "No world-writable files in system paths", High, worldWritable},
		{"VIO-FS-002", "SUID/SGID binaries", Info, suid},
		{"VIO-TIME-001", "Clock synchronized", Low, timeSync},
		{"VIO-DISK-001", "Disk headroom", Medium, diskHeadroom},
		{"VIO-MEM-001", "Swap or enough memory", Low, swap},
		{"VIO-DOCKER-001", "Docker API not exposed", Critical, dockerSocket},
		{"VIO-DOCKER-002", "Docker ports not bypassing the firewall", Medium, dockerPorts},
	}
}

func sudoOK(h *tools.Host) bool { return h.Facts.Root || h.Facts.Sudo }

func sh(ctx context.Context, h *tools.Host, script string) (string, error) {
	return h.Output(ctx, "sh", "-c", script)
}

func sshPort(h *tools.Host) int {
	if h.Facts.SSHPort > 0 {
		return h.Facts.SSHPort
	}
	return 22
}

func firewallActive(_ context.Context, h *tools.Host) Finding {
	switch {
	case h.Facts.FirewallActive:
		return pass(h.Facts.Firewall + " active")
	case h.Facts.Firewall == "ufw" || h.Facts.Firewall == "firewalld":
		f := failed(h.Facts.Firewall+" installed but inactive", fix("fw_enable", map[string]any{}))
		// fw_enable needs the SSH port allowed first; the plan builder adds that.
		return f
	case h.Facts.Firewall == "none" && h.Facts.PkgMgr == "apt":
		return failed("no firewall installed (install ufw)", fix("pkg_install", map[string]any{"names": []string{"ufw"}}))
	}
	return failed("no active firewall ("+h.Facts.Firewall+")", nil)
}

func firewallDefaultDeny(ctx context.Context, h *tools.Host) Finding {
	if h.Facts.Firewall != "ufw" {
		return skip("checked for ufw only")
	}
	if !sudoOK(h) {
		return skip("needs root or sudo")
	}
	out, err := sh(ctx, h, "grep -E '^DEFAULT_INPUT_POLICY=' /etc/default/ufw || true")
	if err != nil {
		return errored(err)
	}
	if strings.Contains(out, "DROP") || strings.Contains(out, "REJECT") {
		return pass(strings.TrimSpace(out))
	}
	return failed(strings.TrimSpace(out), fix("fw_default_deny", map[string]any{}))
}

func publicListeners(ctx context.Context, h *tools.Host) Finding {
	out, err := h.Output(ctx, "ss", "-tulnH")
	if err != nil {
		return errored(err)
	}
	var public []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		local := f[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		addr, port := local[:i], local[i+1:]
		if strings.HasPrefix(addr, "127.") || addr == "[::1]" || strings.HasPrefix(addr, "[::ffff:127.") || strings.HasSuffix(addr, "%lo") {
			continue
		}
		e := f[0] + "/" + port
		if !contains(public, e) {
			public = append(public, e)
		}
	}
	if len(public) == 0 {
		return pass("nothing listens on public interfaces")
	}
	f := Finding{Status: Fail, Severity: Info, Detail: "listening publicly: " + strings.Join(public, ", ")}
	if !h.Facts.FirewallActive && len(public) > 1 {
		f.Severity = Medium
		f.Detail += " (no active firewall)"
	}
	return f
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func securityUpdates(ctx context.Context, h *tools.Host) Finding {
	switch h.Facts.PkgMgr {
	case "apt":
		out, err := sh(ctx, h, "apt list --upgradable 2>/dev/null | grep -c -- -security || true")
		if err != nil {
			return errored(err)
		}
		n, _ := strconv.Atoi(strings.TrimSpace(out))
		if n == 0 {
			return pass("none pending (as of the last apt update)")
		}
		return failed(fmt.Sprintf("%d security updates pending", n), fix("pkg_upgrade", map[string]any{"security": true}))
	case "dnf", "yum":
		res, err := h.Run(ctx, true, h.Facts.PkgMgr, "-q", "check-update", "--security")
		if err != nil {
			return errored(err)
		}
		if res.ExitCode == 0 {
			return pass("none pending")
		}
		if res.ExitCode == 100 {
			n := len(strings.Fields(strings.TrimSpace(string(res.Stdout)))) / 3
			return failed(fmt.Sprintf("%d security updates pending", n), fix("pkg_upgrade", map[string]any{"security": true}))
		}
		return errored(fmt.Errorf("check-update exited %d", res.ExitCode))
	}
	return skip("checked for apt and dnf only")
}

func autoUpdates(ctx context.Context, h *tools.Host) Finding {
	switch h.Facts.PkgMgr {
	case "apt":
		out, err := sh(ctx, h, `dpkg-query -W -f='${db:Status-Abbrev}' unattended-upgrades 2>/dev/null; echo; apt-config dump 2>/dev/null | grep -E 'APT::Periodic::Unattended-Upgrade "1"' || true`)
		if err != nil {
			return errored(err)
		}
		if strings.HasPrefix(out, "ii") && strings.Contains(out, `Unattended-Upgrade "1"`) {
			return pass("unattended-upgrades enabled")
		}
		return failed("unattended-upgrades not enabled", fix("autoupdates_enable", map[string]any{}))
	case "dnf", "yum":
		res, err := h.Run(ctx, false, "systemctl", "is-enabled", "dnf-automatic.timer", "dnf-automatic-install.timer")
		if err != nil {
			return errored(err)
		}
		if strings.Contains(string(res.Stdout), "enabled") {
			return pass("dnf-automatic enabled")
		}
		return failed("dnf-automatic not enabled", fix("autoupdates_enable", map[string]any{}))
	}
	return skip("checked for apt and dnf only")
}

func rebootRequired(ctx context.Context, h *tools.Host) Finding {
	res, err := h.Run(ctx, false, "test", "-e", "/var/run/reboot-required")
	if err != nil {
		return errored(err)
	}
	if res.ExitCode == 0 {
		return failed("/var/run/reboot-required exists (a kernel or libc update is waiting)", nil)
	}
	return pass("no reboot pending")
}

func fail2ban(sshd map[string]string) func(context.Context, *tools.Host) Finding {
	return func(ctx context.Context, h *tools.Host) Finding {
		res, err := h.Run(ctx, false, "sh", "-c", "command -v fail2ban-client >/dev/null && (systemctl is-active fail2ban 2>/dev/null || rc-service fail2ban status 2>/dev/null)")
		if err != nil {
			return errored(err)
		}
		out := string(res.Stdout)
		if res.ExitCode == 0 && (strings.Contains(out, "active") || strings.Contains(out, "started")) {
			return pass("fail2ban running")
		}
		if sshd != nil && sshd["passwordauthentication"] == "no" {
			return pass("no fail2ban, but password logins are off, so guessing can't succeed")
		}
		f := failed("no fail2ban (or equivalent) and password logins may be allowed", fix("fail2ban_configure", map[string]any{}))
		f.Severity = Medium
		return f
	}
}

func uidZero(ctx context.Context, h *tools.Host) Finding {
	out, err := sh(ctx, h, `getent passwd | awk -F: '$3==0 && $1!="root" {print $1}'`)
	if err != nil {
		return errored(err)
	}
	if u := strings.Fields(out); len(u) > 0 {
		return failed("uid 0 accounts besides root: "+strings.Join(u, ", "), nil)
	}
	return pass("only root")
}

func emptyPasswords(ctx context.Context, h *tools.Host) Finding {
	if !sudoOK(h) {
		return skip("needs root or sudo")
	}
	// Prints account names only; hashes never leave the host.
	out, err := sh(ctx, h, `awk -F: '($2==""){print $1}' /etc/shadow`)
	if err != nil {
		return errored(err)
	}
	if u := strings.Fields(out); len(u) > 0 {
		return failed("accounts with empty passwords: "+strings.Join(u, ", "), nil)
	}
	return pass("none")
}

func nopasswd(ctx context.Context, h *tools.Host) Finding {
	if !sudoOK(h) {
		return skip("needs root or sudo")
	}
	out, err := sh(ctx, h, `grep -rhsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null || true`)
	if err != nil {
		return errored(err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if out = strings.TrimSpace(out); out == "" {
		return pass("no NOPASSWD grants")
	}
	return Finding{Status: Fail, Severity: Info, Detail: fmt.Sprintf("%d NOPASSWD grant(s): %s", len(lines), strings.Join(lines, " | "))}
}

func worldWritable(ctx context.Context, h *tools.Host) Finding {
	if !sudoOK(h) {
		return skip("needs root or sudo")
	}
	out, err := sh(ctx, h, `find /etc /usr/bin /usr/sbin /usr/local/bin /bin /sbin -xdev -type f -perm -0002 2>/dev/null | head -n 20`)
	if err != nil {
		return errored(err)
	}
	if f := strings.Fields(out); len(f) > 0 {
		return failed("world-writable: "+strings.Join(f, ", "), nil)
	}
	return pass("none")
}

func suid(ctx context.Context, h *tools.Host) Finding {
	out, err := sh(ctx, h, `find /usr /bin /sbin -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l`)
	if err != nil {
		return errored(err)
	}
	return pass(strings.TrimSpace(out) + " SUID/SGID binaries (inventory; review with fs_grep or run_command find)")
}

func timeSync(ctx context.Context, h *tools.Host) Finding {
	if h.Facts.Init != "systemd" {
		return skip("checked with timedatectl only")
	}
	out, err := h.Output(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err != nil {
		return errored(err)
	}
	if strings.TrimSpace(out) == "yes" {
		return pass("NTP synchronized")
	}
	return failed("clock not NTP-synchronized", nil)
}

func diskHeadroom(ctx context.Context, h *tools.Host) Finding {
	out, err := h.Output(ctx, "df", "-P", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay")
	if err != nil {
		return errored(err)
	}
	worst, where := 0, ""
	for _, line := range strings.Split(out, "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		n, _ := strconv.Atoi(strings.TrimSuffix(f[4], "%"))
		if n > worst {
			worst, where = n, f[5]
		}
	}
	d := fmt.Sprintf("fullest: %s at %d%%", where, worst)
	switch {
	case worst >= 95:
		return Finding{Status: Fail, Severity: High, Detail: d}
	case worst >= 85:
		return Finding{Status: Fail, Severity: Medium, Detail: d}
	}
	return pass(d)
}

func swap(ctx context.Context, h *tools.Host) Finding {
	out, err := sh(ctx, h, `awk '/^MemTotal/{m=$2} /^SwapTotal/{s=$2} END{print m, s}' /proc/meminfo`)
	if err != nil {
		return errored(err)
	}
	f := strings.Fields(out)
	if len(f) != 2 {
		return skip("could not read /proc/meminfo")
	}
	mem, _ := strconv.Atoi(f[0])
	sw, _ := strconv.Atoi(f[1])
	if sw > 0 || mem >= 4*1024*1024 {
		return pass(fmt.Sprintf("memory %d MiB, swap %d MiB", mem/1024, sw/1024))
	}
	return failed(fmt.Sprintf("only %d MiB memory and no swap; the OOM killer may stop services", mem/1024), nil)
}

func dockerSocket(ctx context.Context, h *tools.Host) Finding {
	out, err := sh(ctx, h, `command -v docker >/dev/null || { echo none; exit 0; }
stat -c '%a' /var/run/docker.sock 2>/dev/null || echo nosock
ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E ':(2375|2376)$' || true`)
	if err != nil {
		return errored(err)
	}
	lines := strings.Fields(out)
	if len(lines) > 0 && lines[0] == "none" {
		return skip("docker not installed")
	}
	var bad []string
	if len(lines) > 0 && lines[0] != "nosock" {
		if m, _ := strconv.ParseUint(lines[0], 8, 32); m&0o006 != 0 {
			bad = append(bad, "docker.sock mode "+lines[0]+" (world-accessible)")
		}
	}
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "127.") && !strings.HasPrefix(l, "[::1]") {
			bad = append(bad, "Docker API listening on "+l)
		}
	}
	if len(bad) > 0 {
		return failed(strings.Join(bad, "; "), nil)
	}
	return pass("socket private, API not exposed")
}

func dockerPorts(ctx context.Context, h *tools.Host) Finding {
	if h.Facts.Firewall != "ufw" || !h.Facts.FirewallActive {
		return skip("only relevant with an active ufw")
	}
	out, err := sh(ctx, h, `command -v docker >/dev/null || exit 0; docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:|\[::\]:' || true`)
	if err != nil {
		return errored(err)
	}
	if out = strings.TrimSpace(out); out == "" {
		return pass("no containers publish ports on all interfaces")
	}
	return failed("Docker publishes these ports directly through iptables, bypassing ufw: "+strings.ReplaceAll(out, "\n", "; "), nil)
}

// Tool exposes the baseline to the agent as an observe tool.
type Tool struct{}

func (Tool) Name() string { return "check_run" }
func (Tool) Description() string {
	return "Run vio's deterministic security baseline (SSH, firewall, updates, users, sudo, files, disk, Docker) and list findings with suggested fixes."
}
func (Tool) Schema() json.RawMessage { return json.RawMessage(`{"type":"object","properties":{}}`) }
func (Tool) Tier() plan.Tier         { return plan.Observe }

func (Tool) Observe(ctx context.Context, h *tools.Host, _ json.RawMessage) (tools.Output, error) {
	return tools.Output{Label: "security baseline", Text: Format(h, Run(ctx, h))}, nil
}

// Format renders findings as plain text.
func Format(h *tools.Host, fs []Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %s\n", h.Name, h.Facts.Summary())
	for _, f := range fs {
		mark := map[string]string{Pass: "✓", Fail: "✗", Skip: "-", Error: "!"}[f.Status]
		sev := ""
		if f.Status == Fail {
			sev = f.Severity.String()
		}
		fmt.Fprintf(&b, "  %s %-8s %-14s %s: %s", mark, sev, f.ID, f.Title, f.Detail)
		if f.Fix != nil {
			fmt.Fprintf(&b, "  [fix: %s %s]", f.Fix.Tool, f.Fix.Args)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Fixes returns the fixes for failing findings, in an order that is safe to
// apply: SSH settings first, then the operator's SSH port is allowed before
// the firewall is turned on or set to deny by default.
func Fixes(h *tools.Host, fs []Finding) []Fix {
	var out []Fix
	sshdSettings := map[string]string{}
	needAllow := false
	for _, f := range fs {
		if f.Status != Fail || f.Fix == nil {
			continue
		}
		switch f.Fix.Tool {
		case "sshd_set":
			var in struct{ Settings map[string]string }
			if json.Unmarshal(f.Fix.Args, &in) == nil {
				for k, v := range in.Settings {
					sshdSettings[k] = v
				}
			}
			continue
		case "fw_enable", "fw_default_deny":
			needAllow = true
		}
		out = append(out, *f.Fix)
	}
	if needAllow {
		allow := *fix("fw_allow", map[string]any{"port": sshPort(h), "proto": "tcp"})
		out = append([]Fix{allow}, out...)
	}
	if len(sshdSettings) > 0 {
		// One sshd change, one guarded reload.
		out = append([]Fix{*fix("sshd_set", map[string]any{"settings": sshdSettings})}, out...)
	}
	return out
}

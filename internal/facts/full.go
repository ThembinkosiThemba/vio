package facts

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/transport"
)

// Facts is what tools, adapters and policy need to know about a host.
// See specs/plan.md §5.6.
type Facts struct {
	Basic
	ID       string // os-release ID, e.g. "ubuntu"
	IDLike   string // os-release ID_LIKE, e.g. "debian"
	Version  string // os-release VERSION_ID
	Init     string // systemd | openrc | unknown
	PkgMgr   string // apt | dnf | yum | apk | ""
	Firewall string // ufw | firewalld | nftables | iptables | none
	// FirewallActive is true when the detected firewall is enforcing rules.
	FirewallActive bool
	SSHUnit        string // service name of sshd: "ssh" (Debian) or "sshd"
	SSHPort        int    // server port of the operator's current connection
	ClientIP       string // operator's source address as the host sees it
	Virt           string // systemd-detect-virt output, if available
}

// probeScript prints key=value lines. It only reads state and takes no input.
const probeScript = `
have() { command -v "$1" >/dev/null 2>&1; }
echo "ssh_connection=$SSH_CONNECTION"
if [ -d /run/systemd/system ]; then echo init=systemd; elif have openrc || [ -d /run/openrc ]; then echo init=openrc; else echo init=unknown; fi
for m in apt-get dnf yum apk; do if have $m; then echo pkg=$m; break; fi; done
fw=none; active=no
if have ufw; then fw=ufw; ufw status 2>/dev/null | grep -q '^Status: active' && active=yes; fi
if [ $fw = none ] && have firewall-cmd; then fw=firewalld; firewall-cmd --state >/dev/null 2>&1 && active=yes; fi
if [ $fw = none ] && have nft; then fw=nftables; [ -n "$(nft list ruleset 2>/dev/null)" ] && active=yes; fi
if [ $fw = none ] && have iptables; then fw=iptables; iptables -S 2>/dev/null | grep -qv '^-P .* ACCEPT$' && active=yes; fi
echo fw=$fw; echo fw_active=$active
if [ -e /lib/systemd/system/ssh.service ] || [ -e /usr/lib/systemd/system/ssh.service ] || [ -e /etc/init.d/ssh ]; then echo ssh_unit=ssh; else echo ssh_unit=sshd; fi
have systemd-detect-virt && echo "virt=$(systemd-detect-virt 2>/dev/null)"
true`

// Gather collects Facts. It runs with sudo when available so firewall state is visible.
func Gather(ctx context.Context, x transport.Executor) (Facts, error) {
	b, err := GatherBasic(ctx, x)
	if err != nil {
		return Facts{}, err
	}
	f := Facts{Basic: b, Firewall: "none", Init: "unknown"}
	if data, _, err := x.ReadFile(ctx, "/etc/os-release", 64*1024); err == nil {
		m := ParseOSRelease(string(data))
		f.ID, f.IDLike, f.Version = m["ID"], m["ID_LIKE"], m["VERSION_ID"]
	}
	// SSH_CONNECTION only exists in the unprivileged login environment; sudo
	// would clear it. So probe twice when elevated: once for the connection,
	// once (with sudo) for firewall state.
	res, err := x.Run(ctx, transport.Cmd{Args: []string{"sh", "-c", probeScript}})
	if err != nil {
		return f, fmt.Errorf("facts: %w", err)
	}
	f.parse(string(res.Stdout))
	if b.Sudo && !b.Root {
		if res, err := x.Run(ctx, transport.Cmd{Args: []string{"sh", "-c", probeScript}, Sudo: true}); err == nil && res.ExitCode == 0 {
			conn := f.SSHPort
			ip := f.ClientIP
			f.parse(string(res.Stdout))
			f.SSHPort, f.ClientIP = conn, ip
		}
	}
	return f, nil
}

func (f *Facts) parse(out string) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "ssh_connection":
			// "client_ip client_port server_ip server_port"
			if p := strings.Fields(v); len(p) == 4 {
				f.ClientIP = p[0]
				f.SSHPort, _ = strconv.Atoi(p[3])
			}
		case "init":
			f.Init = v
		case "pkg":
			f.PkgMgr = strings.TrimSuffix(v, "-get")
		case "fw":
			f.Firewall = v
		case "fw_active":
			f.FirewallActive = v == "yes"
		case "ssh_unit":
			f.SSHUnit = v
		case "virt":
			f.Virt = v
		}
	}
}

// Summary is a one-line description, e.g. "Ubuntu 24.04 · systemd · apt · ufw (inactive)".
func (f Facts) Summary() string {
	parts := []string{}
	if f.OS != "" {
		parts = append(parts, f.OS)
	}
	parts = append(parts, f.Init)
	if f.PkgMgr != "" {
		parts = append(parts, f.PkgMgr)
	}
	fw := f.Firewall
	if fw != "none" {
		if f.FirewallActive {
			fw += " (active)"
		} else {
			fw += " (inactive)"
		}
	}
	parts = append(parts, fw)
	return strings.Join(parts, " · ")
}

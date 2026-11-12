package change

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/tools"
	"github.com/ThembinkosiThemba/vio/internal/tools/adapters"
)

// sshPort is the port the operator is connected on, or 22.
func sshPort(h *tools.Host) int {
	if h.Facts.SSHPort > 0 {
		return h.Facts.SSHPort
	}
	return 22
}

// sshAllowed reports whether the configured firewall rules already allow the
// operator's SSH port. Policy uses it to block enabling a firewall that would
// lock the operator out.
func sshAllowed(ctx context.Context, h *tools.Host, fw adapters.FW) (bool, error) {
	out, err := h.Output(ctx, fw.Rules()...)
	if err != nil {
		return false, err
	}
	return fw.Allows(out, sshPort(h)), nil
}

func fwRule(name, verb string) tool {
	desc := "Add a firewall rule allowing inbound traffic to a port, optionally only from a source address or CIDR. Rollback deletes the rule."
	if verb == "deny" {
		desc = "Add a firewall rule denying inbound traffic to a port, optionally only from a source. Rollback deletes the rule."
	}
	return tool{
		name: name, tier: plan.Change, desc: desc,
		schema: `{"type":"object","properties":{
			"port":{"type":"integer"},
			"proto":{"type":"string","enum":["tcp","udp"]},
			"from":{"type":"string","description":"Source IP or CIDR; default any"}},
			"required":["port"]}`,
		plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
			var r adapters.Rule
			if err := tools.Decode(raw, &r); err != nil {
				return plan.Action{}, err
			}
			if r.Port < 1 || r.Port > 65535 {
				return plan.Action{}, errors.New("port must be 1-65535")
			}
			if r.Proto != "" && r.Proto != "tcp" && r.Proto != "udp" {
				return plan.Action{}, errors.New("proto must be tcp or udp")
			}
			if r.From != "" && !validSource(r.From) {
				return plan.Action{}, fmt.Errorf("invalid source %q", r.From)
			}
			fw, err := adapters.FWFor(h.Facts)
			if err != nil {
				return plan.Action{}, err
			}
			do, undo, err := fw.Rule(verb, r)
			if err != nil {
				return plan.Action{}, err
			}
			a := plan.Action{Summary: fmt.Sprintf("%s %s %s", fw.Name(), verb, r), Rollback: &plan.RollbackSpec{Commands: undo}}
			for _, c := range do {
				a.Steps = append(a.Steps, plan.Run(strings.Join(c, " "), c...))
			}
			if verb == "deny" && h.Facts.FirewallActive {
				a.AddRisk(plan.RiskLockout)
			}
			meta(&a, "verb", verb)
			meta(&a, "port", strconv.Itoa(r.Port))
			meta(&a, "ssh_port", strconv.Itoa(sshPort(h)))
			meta(&a, "from", r.From)
			return a, nil
		},
	}
}

// validSource accepts IPv4/IPv6 addresses and CIDRs, or "any".
func validSource(s string) bool {
	if s == "any" {
		return true
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F' || r == '.' || r == ':' || r == '/') {
			return false
		}
	}
	return len(s) <= 64
}

var fwEnable = tool{
	name: "fw_enable", tier: plan.Change,
	desc:   "Turn the firewall on. Policy refuses unless the operator's SSH port is already allowed, or allowed earlier in the same plan (use fw_allow first). Runs under a lockout guard.",
	schema: `{"type":"object","properties":{}}`,
	plan: func(ctx context.Context, h *tools.Host, _ json.RawMessage) (plan.Action, error) {
		fw, err := adapters.FWFor(h.Facts)
		if err != nil {
			return plan.Action{}, err
		}
		if h.Facts.FirewallActive {
			return plan.Action{}, errors.New("the firewall is already active")
		}
		ok, err := sshAllowed(ctx, h, fw)
		if err != nil {
			return plan.Action{}, err
		}
		do, undo := fw.Enable()
		a := plan.Action{Summary: "enable " + fw.Name(), Rollback: &plan.RollbackSpec{Commands: undo}, Risk: []plan.Risk{plan.RiskLockout}}
		for _, c := range do {
			a.Steps = append(a.Steps, plan.Run(strings.Join(c, " "), c...))
		}
		meta(&a, "ssh_port", strconv.Itoa(sshPort(h)))
		meta(&a, "ssh_allowed", strconv.FormatBool(ok))
		return a, nil
	},
}

var fwDefaultDeny = tool{
	name: "fw_default_deny", tier: plan.Dangerous,
	desc:   "Set the firewall's default inbound policy to deny (ufw). Policy refuses unless the operator's SSH port is allowed. Runs under a lockout guard.",
	schema: `{"type":"object","properties":{}}`,
	plan: func(ctx context.Context, h *tools.Host, _ json.RawMessage) (plan.Action, error) {
		fw, err := adapters.FWFor(h.Facts)
		if err != nil {
			return plan.Action{}, err
		}
		prev := "allow"
		if out, err := h.Output(ctx, "sh", "-c", "grep -E '^DEFAULT_INPUT_POLICY=' /etc/default/ufw || true"); err == nil {
			switch {
			case strings.Contains(out, "DROP"):
				return plan.Action{}, errors.New("the default inbound policy is already deny")
			case strings.Contains(out, "REJECT"):
				prev = "reject"
			}
		}
		do, undo, err := fw.DefaultDenyIncoming(prev)
		if err != nil {
			return plan.Action{}, err
		}
		ok, err := sshAllowed(ctx, h, fw)
		if err != nil {
			return plan.Action{}, err
		}
		a := plan.Action{Summary: fw.Name() + " default deny incoming", Rollback: &plan.RollbackSpec{Commands: undo}, Risk: []plan.Risk{plan.RiskLockout}}
		for _, c := range do {
			a.Steps = append(a.Steps, plan.Run(strings.Join(c, " "), c...))
		}
		meta(&a, "ssh_port", strconv.Itoa(sshPort(h)))
		meta(&a, "ssh_allowed", strconv.FormatBool(ok))
		return a, nil
	},
}

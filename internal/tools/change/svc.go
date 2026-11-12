package change

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/tools"
	"github.com/ThembinkosiThemba/vio/internal/tools/adapters"
)

var svcControl = tool{
	name: "svc_control", tier: plan.Change,
	desc: "Start, stop, restart, reload, enable or disable a service. Rollback returns it to its previous state.",
	schema: `{"type":"object","properties":{
		"name":{"type":"string","description":"Service name, e.g. nginx"},
		"action":{"type":"string","enum":["start","stop","restart","reload","enable","disable"]}},
		"required":["name","action"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ Name, Action string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := checkName("service", in.Name); err != nil {
			return plan.Action{}, err
		}
		sm, err := adapters.SvcFor(h.Facts)
		if err != nil {
			return plan.Action{}, err
		}
		do, err := sm.Action(in.Action, in.Name)
		if err != nil {
			return plan.Action{}, err
		}
		out, err := h.Output(ctx, sm.State(in.Name)...)
		if err != nil {
			return plan.Action{}, err
		}
		state := strings.Fields(out)
		if len(state) != 2 {
			return plan.Action{}, fmt.Errorf("could not read the state of %s", in.Name)
		}
		active, enabled := state[0] == "active", state[1] == "enabled"
		switch {
		case in.Action == "start" && active, in.Action == "stop" && !active:
			return plan.Action{}, fmt.Errorf("%s is already %s", in.Name, state[0])
		case in.Action == "enable" && enabled, in.Action == "disable" && !enabled:
			return plan.Action{}, fmt.Errorf("%s is already %s", in.Name, state[1])
		}
		undo, _ := sm.Action(adapters.Inverse(in.Action, active, enabled), in.Name)
		a := plan.Action{
			Summary:  fmt.Sprintf("%s %s", in.Action, in.Name),
			Diff:     fmt.Sprintf("  %s: %s, %s (before)\n", in.Name, state[0], state[1]),
			Steps:    []plan.Step{plan.Run(in.Action+" "+in.Name, do...)},
			Rollback: &plan.RollbackSpec{Commands: [][]string{undo}},
		}
		if slices.Contains([]string{"stop", "restart", "reload"}, in.Action) {
			a.AddRisk(plan.RiskDowntime)
		}
		if isSSH(h, in.Name) && in.Action != "start" && in.Action != "enable" {
			a.AddRisk(plan.RiskLockout)
		}
		if slices.Contains([]string{"start", "restart", "reload"}, in.Action) {
			a.Verify = append(a.Verify, stateProbe(in.Name+" is active", sm.State(in.Name), "active"))
		}
		meta(&a, "service", in.Name)
		meta(&a, "action", in.Action)
		return a, nil
	},
}

func isSSH(h *tools.Host, unit string) bool {
	u := strings.TrimSuffix(unit, ".service")
	return u == "ssh" || u == "sshd" || u == h.Facts.SSHUnit || u == "ssh.socket"
}

// sshdDirectives are the settings sshd_set may change.
var sshdDirectives = map[string]string{}

func init() {
	for _, d := range []string{
		"PasswordAuthentication", "PermitRootLogin", "PubkeyAuthentication", "KbdInteractiveAuthentication",
		"ChallengeResponseAuthentication", "PermitEmptyPasswords", "X11Forwarding", "MaxAuthTries",
		"LoginGraceTime", "ClientAliveInterval", "ClientAliveCountMax", "AllowTcpForwarding",
		"AllowAgentForwarding", "AllowUsers", "AllowGroups", "MaxSessions", "LogLevel", "UsePAM",
		"Ciphers", "MACs", "KexAlgorithms", "PermitUserEnvironment", "Banner",
	} {
		sshdDirectives[strings.ToLower(d)] = d
	}
}

const sshdConfig = "/etc/ssh/sshd_config"

// SetSSHDirectives rewrites an sshd_config so each setting appears once, at the
// top of the file. sshd uses the first value it reads, and distro drop-ins are
// included near the top, so vio's lines must come before any Include.
// Directives inside Match blocks are left alone.
func SetSSHDirectives(config string, settings map[string]string) string {
	var kept []string
	inMatch := false
	for _, line := range strings.Split(strings.TrimSuffix(config, "\n"), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.EqualFold(f[0], "Match") {
			inMatch = true
		}
		if line == managedHeader {
			continue
		}
		if !inMatch && len(f) > 0 {
			if _, ok := settings[sshdDirectives[strings.ToLower(f[0])]]; ok {
				continue
			}
		}
		kept = append(kept, line)
	}
	var b strings.Builder
	b.WriteString(managedHeader + "\n")
	for _, k := range slices.Sorted(maps.Keys(settings)) {
		fmt.Fprintf(&b, "%s %s\n", k, settings[k])
	}
	for _, l := range kept {
		b.WriteString(l + "\n")
	}
	return b.String()
}

const managedHeader = "# Set by vio (sshd uses the first value it reads, so these stay at the top)"

var sshdSet = tool{
	name: "sshd_set", tier: plan.Change,
	desc: "Change SSH server settings, e.g. {\"PasswordAuthentication\":\"no\"}. The config is validated with sshd -t, " +
		"sshd is reloaded under a lockout guard, and a fresh login must succeed or the change reverts automatically.",
	schema: `{"type":"object","properties":{
		"settings":{"type":"object","additionalProperties":{"type":"string"},"description":"Directive → value"}},
		"required":["settings"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ Settings map[string]string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if len(in.Settings) == 0 {
			return plan.Action{}, errors.New("settings is required")
		}
		settings := map[string]string{}
		for k, v := range in.Settings {
			d, ok := sshdDirectives[strings.ToLower(k)]
			if !ok {
				return plan.Action{}, fmt.Errorf("sshd_set doesn't manage %q (Port and ListenAddress must be changed by hand, then the inventory updated)", k)
			}
			v = strings.TrimSpace(v)
			if v == "" || strings.ContainsAny(v, "\n\r#") {
				return plan.Action{}, fmt.Errorf("invalid value for %s", d)
			}
			settings[d] = v
		}
		e, err := readForEdit(ctx, h, sshdConfig)
		if err != nil {
			return plan.Action{}, err
		}
		if !e.exists {
			return plan.Action{}, fmt.Errorf("%s not found", sshdConfig)
		}
		var a plan.Action
		var parts []string
		for _, k := range slices.Sorted(maps.Keys(settings)) {
			parts = append(parts, k+"="+settings[k])
			meta(&a, "sshd."+strings.ToLower(k), strings.ToLower(settings[k]))
			want := strings.ToLower(k + " " + settings[k])
			if k == "AllowUsers" || k == "AllowGroups" || k == "Ciphers" || k == "MACs" || k == "KexAlgorithms" || k == "Banner" {
				want = strings.ToLower(k) + " "
			}
			a.Verify = append(a.Verify, plan.Probe{Kind: plan.ProbeCmd, Desc: "sshd -T shows " + k, Args: []string{"sshd", "-T"}, Want: want})
		}
		a.Summary = "sshd " + strings.Join(parts, " ")
		e.write(&a, SetSSHDirectives(string(e.before), settings), "0644", "root:root")
		a.Steps = append(a.Steps, plan.Run("validate with sshd -t", "sshd", "-t"))
		reload := []string{"systemctl", "try-reload-or-restart", "--", unitOr(h.Facts.SSHUnit, "ssh")}
		if h.Facts.Init == "openrc" {
			reload = []string{"rc-service", "sshd", "reload"}
		}
		a.Steps = append(a.Steps, plan.Run("reload sshd", reload...))
		rollback(&a).Commands = append(rollback(&a).Commands, reload)
		a.AddRisk(plan.RiskLockout)
		meta(&a, "login_user", h.Facts.User)
		return a, nil
	},
}

func unitOr(u, def string) string {
	if u == "" {
		return def
	}
	return u
}

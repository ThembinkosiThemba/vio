package change

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/tools"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

const aptAutoUpgrades = `// Set by vio: refresh package lists and install security updates daily.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
`

var autoupdatesEnable = tool{
	name: "autoupdates_enable", tier: plan.Change,
	desc:   "Turn on automatic security updates: unattended-upgrades on Debian/Ubuntu, dnf-automatic on RHEL-family hosts.",
	schema: `{"type":"object","properties":{}}`,
	plan: func(ctx context.Context, h *tools.Host, _ json.RawMessage) (plan.Action, error) {
		var a plan.Action
		switch h.Facts.PkgMgr {
		case "apt":
			if _, err := planInstall(ctx, h, &a, "unattended-upgrades"); err != nil {
				return a, err
			}
			e, err := readForEdit(ctx, h, "/etc/apt/apt.conf.d/20auto-upgrades")
			if err != nil {
				return a, err
			}
			if string(e.before) == aptAutoUpgrades {
				return a, errors.New("automatic updates are already enabled by vio")
			}
			e.write(&a, aptAutoUpgrades, "0644", "root:root")
			a.Summary = "enable unattended-upgrades"
		case "dnf", "yum":
			if _, err := planInstall(ctx, h, &a, "dnf-automatic"); err != nil {
				return a, err
			}
			e, err := readForEdit(ctx, h, "/etc/dnf/automatic.conf")
			if err != nil {
				return a, err
			}
			if e.exists {
				conf := regexp.MustCompile(`(?m)^upgrade_type\s*=.*$`).ReplaceAllString(string(e.before), "upgrade_type = security")
				conf = regexp.MustCompile(`(?m)^apply_updates\s*=.*$`).ReplaceAllString(conf, "apply_updates = yes")
				if conf != string(e.before) {
					e.write(&a, conf, "0644", "root:root")
				}
			}
			a.Steps = append(a.Steps, plan.Run("enable dnf-automatic", "systemctl", "enable", "--now", "dnf-automatic.timer"))
			rollback(&a).Commands = append(rollback(&a).Commands, []string{"systemctl", "disable", "--now", "dnf-automatic.timer"})
			a.Summary = "enable dnf-automatic (security updates)"
		default:
			return a, fmt.Errorf("automatic updates aren't supported for %q yet", h.Facts.PkgMgr)
		}
		return a, nil
	},
}

var fail2banConfigure = tool{
	name: "fail2ban_configure", tier: plan.Change,
	desc: "Install fail2ban if needed and protect SSH with a jail. The operator's current IP is never banned. Rollback restores the previous state.",
	schema: `{"type":"object","properties":{
		"maxretry":{"type":"integer","description":"Failures before a ban, default 5"},
		"bantime":{"type":"string","description":"e.g. 1h, default 1h"},
		"findtime":{"type":"string","description":"e.g. 10m, default 10m"}}}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct {
			MaxRetry          int `json:"maxretry"`
			BanTime, FindTime string
		}
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if in.MaxRetry <= 0 {
			in.MaxRetry = 5
		}
		dur := regexp.MustCompile(`^[0-9]+[smhdw]?$`)
		if in.BanTime == "" {
			in.BanTime = "1h"
		}
		if in.FindTime == "" {
			in.FindTime = "10m"
		}
		if !dur.MatchString(in.BanTime) || !dur.MatchString(in.FindTime) {
			return plan.Action{}, errors.New("bantime and findtime look like 1h, 10m, 600")
		}
		var a plan.Action
		if _, err := planInstall(ctx, h, &a, "fail2ban"); err != nil {
			return a, err
		}
		ignore := "127.0.0.1/8 ::1"
		if ip := h.Facts.ClientIP; ip != "" && validSource(ip) {
			ignore += " " + ip
		}
		backend := "auto"
		if h.Facts.Init == "systemd" {
			backend = "systemd"
		}
		conf := fmt.Sprintf(`# Set by vio.
[sshd]
enabled  = true
port     = %d
backend  = %s
maxretry = %d
findtime = %s
bantime  = %s
ignoreip = %s
`, sshPort(h), backend, in.MaxRetry, in.FindTime, in.BanTime, ignore)
		e, err := readForEdit(ctx, h, "/etc/fail2ban/jail.d/vio-sshd.local")
		if err != nil {
			return a, err
		}
		if string(e.before) == conf {
			return a, errors.New("fail2ban is already configured this way")
		}
		e.write(&a, conf, "0644", "root:root")
		a.Steps = append(a.Steps, plan.Run("validate fail2ban config", "fail2ban-client", "-t"))
		restart := []string{"systemctl", "restart", "fail2ban"}
		enable := []string{"systemctl", "enable", "fail2ban"}
		if h.Facts.Init == "openrc" {
			restart, enable = []string{"rc-service", "fail2ban", "restart"}, []string{"rc-update", "add", "fail2ban", "default"}
		}
		a.Steps = append(a.Steps, plan.Run("enable fail2ban", enable...), plan.Run("restart fail2ban", restart...))
		// The engine restores the old jail file first; the restart picks it up, and
		// then a newly installed fail2ban is removed again.
		rb := rollback(&a)
		rb.Commands = append([][]string{{"sh", "-c", "systemctl restart fail2ban 2>/dev/null || rc-service fail2ban restart 2>/dev/null || true"}}, rb.Commands...)
		a.Verify = append(a.Verify, plan.Probe{Kind: plan.ProbeCmd, Desc: "sshd jail is running", Args: []string{"fail2ban-client", "status", "sshd"}, Want: "Status for the jail"})
		a.Summary = fmt.Sprintf("fail2ban sshd jail (maxretry %d, bantime %s)", in.MaxRetry, in.BanTime)
		return a, nil
	},
}

var onCalendarRE = regexp.MustCompile(`^[A-Za-z0-9*:.,/ ~-]{1,64}$`)

var timerAdd = tool{
	name: "timer_add", tier: plan.Change,
	desc: "Schedule a command with a systemd timer (vio-<name>.service + .timer). schedule is an OnCalendar expression such as daily, hourly or *-*-* 03:00:00.",
	schema: `{"type":"object","properties":{
		"name":{"type":"string","description":"Short name, e.g. backup"},
		"command":{"type":"array","items":{"type":"string"},"description":"argv; the first element must be an absolute path"},
		"schedule":{"type":"string"},
		"user":{"type":"string","description":"Run as this user, default root"}},
		"required":["name","command","schedule"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct {
			Name, Schedule, User string
			Command              []string
		}
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if h.Facts.Init != "systemd" {
			return plan.Action{}, errors.New("timers need systemd")
		}
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`).MatchString(in.Name) {
			return plan.Action{}, errors.New("name: lowercase letters, digits and dashes")
		}
		if len(in.Command) == 0 || checkPath(in.Command[0]) != nil {
			return plan.Action{}, errors.New("command[0] must be an absolute path")
		}
		if !onCalendarRE.MatchString(in.Schedule) {
			return plan.Action{}, errors.New("invalid schedule")
		}
		if in.User != "" {
			if err := checkUser(in.User); err != nil {
				return plan.Action{}, err
			}
		}
		var exec []string
		for _, arg := range in.Command {
			if strings.ContainsAny(arg, "\n\r%$") {
				return plan.Action{}, errors.New("command arguments may not contain newlines, % or $")
			}
			exec = append(exec, transport.Quote(arg))
		}
		unit := "vio-" + in.Name
		svc := fmt.Sprintf("# Set by vio.\n[Unit]\nDescription=vio timer %s\n\n[Service]\nType=oneshot\nExecStart=%s\n", in.Name, strings.Join(exec, " "))
		if in.User != "" {
			svc += "User=" + in.User + "\n"
		}
		tmr := fmt.Sprintf("# Set by vio.\n[Unit]\nDescription=vio timer %s\n\n[Timer]\nOnCalendar=%s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n", in.Name, in.Schedule)

		var a plan.Action
		for _, f := range []struct{ path, content string }{
			{"/etc/systemd/system/" + unit + ".service", svc},
			{"/etc/systemd/system/" + unit + ".timer", tmr},
		} {
			e, err := readForEdit(ctx, h, f.path)
			if err != nil {
				return a, err
			}
			e.write(&a, f.content, "0644", "root:root")
		}
		a.Steps = append(a.Steps,
			plan.Run("check schedule", "systemd-analyze", "calendar", "--", in.Schedule),
			plan.Run("reload systemd units", "systemctl", "daemon-reload"),
			plan.Run("start "+unit+".timer", "systemctl", "enable", "--now", unit+".timer"))
		rollback(&a).Commands = [][]string{{"sh", "-c", `systemctl disable --now "$1" 2>/dev/null; systemctl daemon-reload`, "sh", unit + ".timer"}}
		a.Verify = []plan.Probe{{Kind: plan.ProbeCmd, Desc: unit + ".timer is active", Args: []string{"systemctl", "is-active", unit + ".timer"}, Want: "active"}}
		a.Summary = fmt.Sprintf("timer %s (%s): %s", unit, in.Schedule, strings.Join(in.Command, " "))
		return a, nil
	},
}

var shellExec = tool{
	name: "shell_exec", tier: plan.Dangerous,
	desc: "Run an arbitrary command as root. Last resort when no typed tool fits: it has no diff and no rollback, so it is marked irreversible and always needs explicit approval. Pass argv, not a shell string.",
	schema: `{"type":"object","properties":{
		"command":{"type":"array","items":{"type":"string"}},
		"reason":{"type":"string","description":"Why no typed tool fits"}},
		"required":["command","reason"]}`,
	plan: func(_ context.Context, _ *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct {
			Command []string
			Reason  string
		}
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if len(in.Command) == 0 || in.Command[0] == "" {
			return plan.Action{}, errors.New("command is required")
		}
		if strings.TrimSpace(in.Reason) == "" {
			return plan.Action{}, errors.New("reason is required")
		}
		line := transport.CommandLine(transport.Cmd{Args: in.Command})
		a := plan.Action{
			Summary: "run: " + line,
			Diff:    "  reason: " + in.Reason + "\n",
			Steps:   []plan.Step{plan.Run(line, in.Command...)},
			Risk:    []plan.Risk{plan.RiskIrreversible},
		}
		return a, nil
	},
}

var hostReboot = tool{
	name: "host_reboot", tier: plan.Dangerous,
	desc:   "Reboot the host one minute after approval. Services go down until it is back.",
	schema: `{"type":"object","properties":{"reason":{"type":"string"}},"required":["reason"]}`,
	plan: func(_ context.Context, _ *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ Reason string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		return plan.Action{
			Summary: "reboot (" + in.Reason + ")",
			Steps:   []plan.Step{plan.Run("schedule reboot in 1 minute", "shutdown", "-r", "+1", "vio: "+in.Reason)},
			Risk:    []plan.Risk{plan.RiskIrreversible, plan.RiskDowntime},
		}, nil
	},
}

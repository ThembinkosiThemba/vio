package change

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/redact"
	"github.com/ThembinkosiThemba/vio/internal/tools"
)

// validator is a native config check run after writing a file under prefix,
// before anything reloads. A failure rolls the write back.
type validator struct {
	prefix string
	argv   []string
	risk   plan.Risk
}

var validators = []validator{
	{"/etc/ssh/sshd_config", []string{"sshd", "-t"}, plan.RiskLockout},
	{"/etc/sudoers", []string{"visudo", "-c"}, plan.RiskLockout},
	{"/etc/nginx/", []string{"nginx", "-t"}, plan.RiskDowntime},
	{"/etc/caddy/Caddyfile", []string{"caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"}, plan.RiskDowntime},
	{"/etc/apache2/", []string{"apache2ctl", "configtest"}, plan.RiskDowntime},
	{"/etc/httpd/", []string{"apachectl", "configtest"}, plan.RiskDowntime},
	{"/etc/fail2ban/", []string{"fail2ban-client", "-t"}, ""},
}

// lockoutPaths are files whose contents control access to the host.
var lockoutPaths = []string{"/etc/ssh/", "/etc/sudoers", "/etc/pam.d/", "/etc/ufw/", "/etc/nftables", "/etc/iptables/",
	"/etc/firewalld/", "/etc/security/", "/etc/hosts.allow", "/etc/hosts.deny", "/etc/network/", "/etc/netplan/"}

// addFileChecks adds validators, risks and the optional service reload for a written path.
func addFileChecks(h *tools.Host, a *plan.Action, path, reload string) error {
	for _, v := range validators {
		if strings.HasPrefix(path, v.prefix) {
			a.Steps = append(a.Steps, plan.Run("validate with "+v.argv[0], v.argv...))
			if v.risk != "" {
				a.AddRisk(v.risk)
			}
		}
	}
	for _, p := range lockoutPaths {
		if strings.HasPrefix(path, p) {
			a.AddRisk(plan.RiskLockout)
		}
	}
	if strings.Contains(path, "/.ssh/authorized_keys") {
		a.AddRisk(plan.RiskLockout)
	}
	if strings.HasPrefix(path, "/etc/systemd/system/") && h.Facts.Init == "systemd" {
		a.Steps = append(a.Steps, plan.Run("reload systemd units", "systemctl", "daemon-reload"))
		rollback(a).Commands = append(rollback(a).Commands, []string{"systemctl", "daemon-reload"})
	}
	if reload != "" {
		if err := checkName("service", reload); err != nil {
			return err
		}
		argv := []string{"systemctl", "reload-or-restart", "--", reload}
		if h.Facts.Init == "openrc" {
			argv = []string{"rc-service", reload, "reload"}
		}
		a.Steps = append(a.Steps, plan.Run("reload "+reload, argv...))
		rollback(a).Commands = append(rollback(a).Commands, argv)
		a.AddRisk(plan.RiskDowntime)
	}
	return nil
}

var fsWrite = tool{
	name: "fs_write", tier: plan.Change,
	desc: "Write a whole file (create or replace). Shows a diff; the old file is backed up and restored on rollback. " +
		"Config files are validated natively (sshd -t, nginx -t, visudo -c, ...) before anything reloads. " +
		"Use secret://NAME for secret values; vio fills them from the operator's environment at apply time.",
	schema: `{"type":"object","properties":{
		"path":{"type":"string","description":"Absolute path"},
		"content":{"type":"string","description":"Full new file content"},
		"mode":{"type":"string","description":"Octal mode for new files, default 0644"},
		"owner":{"type":"string","description":"user:group for new files, default root"},
		"reload":{"type":"string","description":"Service to reload after writing, e.g. nginx"}},
		"required":["path","content"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ Path, Content, Mode, Owner, Reload string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := checkPath(in.Path); err != nil {
			return plan.Action{}, err
		}
		if bad, why := redact.Forbidden(in.Path); bad {
			return plan.Action{}, fmt.Errorf("%s holds %s; vio doesn't write it", in.Path, why)
		}
		e, err := readForEdit(ctx, h, in.Path)
		if err != nil {
			return plan.Action{}, err
		}
		if e.exists && string(e.before) == in.Content {
			return plan.Action{}, errors.New("the file already has this content")
		}
		mode := in.Mode
		if mode == "" {
			mode = "0644"
		}
		var a plan.Action
		verb := "create"
		if e.exists {
			verb = "rewrite"
		}
		a.Summary = verb + " " + in.Path
		e.write(&a, in.Content, mode, in.Owner)
		meta(&a, "path", in.Path)
		return a, addFileChecks(h, &a, in.Path, in.Reload)
	},
}

var fsPatch = tool{
	name: "fs_patch", tier: plan.Change,
	desc: "Edit a file by replacing an exact snippet. old must match exactly once unless replace_all is set. " +
		"Shows a diff; validated and backed up like fs_write.",
	schema: `{"type":"object","properties":{
		"path":{"type":"string"},
		"old":{"type":"string","description":"Exact existing text"},
		"new":{"type":"string","description":"Replacement text"},
		"replace_all":{"type":"boolean"},
		"reload":{"type":"string","description":"Service to reload after editing"}},
		"required":["path","old","new"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct {
			Path, Old, New, Reload string
			ReplaceAll             bool `json:"replace_all"`
		}
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := checkPath(in.Path); err != nil {
			return plan.Action{}, err
		}
		if bad, why := redact.Forbidden(in.Path); bad {
			return plan.Action{}, fmt.Errorf("%s holds %s; vio doesn't edit it", in.Path, why)
		}
		if in.Old == "" || in.Old == in.New {
			return plan.Action{}, errors.New("old must be non-empty and differ from new")
		}
		e, err := readForEdit(ctx, h, in.Path)
		if err != nil {
			return plan.Action{}, err
		}
		if !e.exists {
			return plan.Action{}, fmt.Errorf("%s does not exist; use fs_write to create it", in.Path)
		}
		n := strings.Count(string(e.before), in.Old)
		switch {
		case n == 0:
			return plan.Action{}, errors.New("old text not found; read the file again and copy it exactly")
		case n > 1 && !in.ReplaceAll:
			return plan.Action{}, fmt.Errorf("old text matches %d times; include more context or set replace_all", n)
		}
		after := strings.Replace(string(e.before), in.Old, in.New, map[bool]int{true: -1, false: 1}[in.ReplaceAll])
		a := plan.Action{Summary: "edit " + in.Path}
		e.write(&a, after, "", "")
		meta(&a, "path", in.Path)
		return a, addFileChecks(h, &a, in.Path, in.Reload)
	},
}

var fsRemove = tool{
	name: "fs_remove", tier: plan.Dangerous,
	desc:   "Delete a file or directory (recursively). It is backed up first, so rollback restores it. Policy only allows paths under /tmp, /var/tmp and /var/log by default.",
	schema: `{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ Path string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := checkPath(in.Path); err != nil {
			return plan.Action{}, err
		}
		out, err := h.Output(ctx, "sh", "-c", `[ -e "$1" ] || [ -L "$1" ] || { echo absent; exit 0; }; du -sh -- "$1" | cut -f1`, "sh", in.Path)
		if err != nil {
			return plan.Action{}, err
		}
		size := strings.TrimSpace(out)
		if size == "absent" {
			return plan.Action{}, fmt.Errorf("%s does not exist", in.Path)
		}
		a := plan.Action{
			Summary:  fmt.Sprintf("remove %s (%s)", in.Path, size),
			Steps:    []plan.Step{plan.Run("remove "+in.Path, "rm", "-rf", "--", in.Path)},
			Rollback: &plan.RollbackSpec{Restore: []string{in.Path}},
			Risk:     []plan.Risk{plan.RiskDataLoss},
		}
		meta(&a, "path", in.Path)
		return a, nil
	},
}

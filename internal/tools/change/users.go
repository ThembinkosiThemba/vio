package change

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/tools"
)

type account struct {
	name, home, group string
	uid               int
}

// lookupUser returns the account, or exists=false.
func lookupUser(ctx context.Context, h *tools.Host, name string) (account, bool, error) {
	res, err := h.Run(ctx, false, "getent", "passwd", "--", name)
	if err != nil {
		return account{}, false, err
	}
	if res.ExitCode == 2 {
		return account{}, false, nil
	}
	f := strings.Split(strings.TrimSpace(string(res.Stdout)), ":")
	if res.ExitCode != 0 || len(f) < 7 {
		return account{}, false, fmt.Errorf("getent passwd %s failed", name)
	}
	u := account{name: f[0], home: f[5]}
	u.uid, _ = strconv.Atoi(f[2])
	g, err := h.Output(ctx, "id", "-gn", "--", name)
	if err != nil {
		return u, true, err
	}
	u.group = strings.TrimSpace(g)
	return u, true, nil
}

func checkUser(name string) error {
	if !userRE.MatchString(name) {
		return fmt.Errorf("invalid user name %q", name)
	}
	return nil
}

func adminGroup(h *tools.Host) string {
	switch h.Facts.PkgMgr {
	case "apt":
		return "sudo"
	}
	return "wheel"
}

var userAdd = tool{
	name: "user_add", tier: plan.Change,
	desc: "Create a user with a home directory, optionally in the admin group (sudo or wheel). No password is set; add a key with key_add. Rollback deletes the user and home.",
	schema: `{"type":"object","properties":{
		"name":{"type":"string"},
		"admin":{"type":"boolean","description":"Add to the sudo/wheel group"},
		"shell":{"type":"string","description":"Default /bin/bash, or /bin/sh where bash is missing"}},
		"required":["name"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct {
			Name, Shell string
			Admin       bool
		}
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := checkUser(in.Name); err != nil {
			return plan.Action{}, err
		}
		if _, exists, err := lookupUser(ctx, h, in.Name); err != nil {
			return plan.Action{}, err
		} else if exists {
			return plan.Action{}, fmt.Errorf("user %s already exists", in.Name)
		}
		if in.Shell == "" {
			in.Shell = "/bin/bash"
			if h.Facts.PkgMgr == "apk" {
				in.Shell = "/bin/sh"
			}
		}
		if err := checkPath(in.Shell); err != nil {
			return plan.Action{}, err
		}
		add := []string{"useradd", "-m", "-s", in.Shell, "--", in.Name}
		del := []string{"userdel", "-r", "--", in.Name}
		if h.Facts.PkgMgr == "apk" {
			add = []string{"adduser", "-D", "-s", in.Shell, in.Name}
			del = []string{"deluser", "--remove-home", in.Name}
		}
		a := plan.Action{
			Summary:  "create user " + in.Name,
			Steps:    []plan.Step{plan.Run("create user "+in.Name, add...)},
			Rollback: &plan.RollbackSpec{Commands: [][]string{del}},
			Verify:   []plan.Probe{{Kind: plan.ProbeCmd, Desc: in.Name + " exists", Args: []string{"id", "-u", "--", in.Name}}},
		}
		if in.Admin {
			g := adminGroup(h)
			a.Summary += " (admin: " + g + ")"
			a.Steps = append(a.Steps, plan.Run("add "+in.Name+" to "+g, "usermod", "-aG", g, "--", in.Name))
		}
		meta(&a, "user", in.Name)
		return a, nil
	},
}

var userLock = tool{
	name: "user_lock", tier: plan.Change,
	desc:   "Lock a user account: disables password login and expires the account so key logins stop too. Rollback unlocks it. Policy refuses to lock the operator's own login user.",
	schema: `{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ Name string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := checkUser(in.Name); err != nil {
			return plan.Action{}, err
		}
		if _, exists, err := lookupUser(ctx, h, in.Name); err != nil {
			return plan.Action{}, err
		} else if !exists {
			return plan.Action{}, fmt.Errorf("no user %s", in.Name)
		}
		a := plan.Action{
			Summary:  "lock user " + in.Name,
			Steps:    []plan.Step{plan.Run("lock "+in.Name, "usermod", "-L", "-e", "1", "--", in.Name)},
			Rollback: &plan.RollbackSpec{Commands: [][]string{{"usermod", "-U", "-e", "", "--", in.Name}}},
			Risk:     []plan.Risk{plan.RiskLockout},
		}
		meta(&a, "user", in.Name)
		meta(&a, "login_user", h.Facts.User)
		return a, nil
	},
}

var userRemove = tool{
	name: "user_remove", tier: plan.Dangerous,
	desc:   "Delete a user account, and with remove_home its home directory. Irreversible. Policy refuses the operator's own login user.",
	schema: `{"type":"object","properties":{"name":{"type":"string"},"remove_home":{"type":"boolean"}},"required":["name"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct {
			Name       string
			RemoveHome bool `json:"remove_home"`
		}
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := checkUser(in.Name); err != nil {
			return plan.Action{}, err
		}
		u, exists, err := lookupUser(ctx, h, in.Name)
		if err != nil {
			return plan.Action{}, err
		}
		if !exists {
			return plan.Action{}, fmt.Errorf("no user %s", in.Name)
		}
		if u.uid == 0 {
			return plan.Action{}, errors.New("refusing to remove a uid 0 account")
		}
		argv := []string{"userdel", "--", in.Name}
		a := plan.Action{Summary: "delete user " + in.Name, Risk: []plan.Risk{plan.RiskIrreversible, plan.RiskLockout}}
		if in.RemoveHome {
			argv = []string{"userdel", "-r", "--", in.Name}
			a.Summary += " and " + u.home
			a.AddRisk(plan.RiskDataLoss)
		}
		a.Steps = []plan.Step{plan.Run(a.Summary, argv...)}
		meta(&a, "user", in.Name)
		meta(&a, "login_user", h.Facts.User)
		return a, nil
	},
}

func authorizedKeys(u account) string { return path.Join(u.home, ".ssh", "authorized_keys") }

var keyAdd = tool{
	name: "key_add", tier: plan.Change,
	desc: "Add an SSH public key to a user's ~/.ssh/authorized_keys. Rollback restores the previous file.",
	schema: `{"type":"object","properties":{
		"user":{"type":"string"},
		"key":{"type":"string","description":"One public key line, e.g. ssh-ed25519 AAAA... comment"}},
		"required":["user","key"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ User, Key string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := checkUser(in.User); err != nil {
			return plan.Action{}, err
		}
		line := strings.TrimSpace(in.Key)
		pub, comment, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil || len(strings.TrimSpace(string(rest))) > 0 || strings.Contains(line, "\n") {
			return plan.Action{}, errors.New("key must be exactly one valid public key line")
		}
		if strings.Contains(line, "PRIVATE KEY") {
			return plan.Action{}, errors.New("that is a private key; never share it")
		}
		u, exists, err := lookupUser(ctx, h, in.User)
		if err != nil {
			return plan.Action{}, err
		}
		if !exists {
			return plan.Action{}, fmt.Errorf("no user %s", in.User)
		}
		file := authorizedKeys(u)
		e, err := readForEdit(ctx, h, file)
		if err != nil {
			return plan.Action{}, err
		}
		fp := ssh.FingerprintSHA256(pub)
		for _, l := range strings.Split(string(e.before), "\n") {
			if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil && ssh.FingerprintSHA256(k) == fp {
				return plan.Action{}, fmt.Errorf("%s already has key %s", in.User, fp)
			}
		}
		content := string(e.before)
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
		}
		content += line + "\n"
		owner := u.name + ":" + u.group
		a := plan.Action{Summary: fmt.Sprintf("add key %s %s to %s", fp, comment, in.User)}
		a.Steps = append(a.Steps, plan.Run("ensure "+path.Dir(file), "install", "-d", "-m", "700", "-o", u.name, "-g", u.group, "--", path.Dir(file)))
		e.write(&a, content, "0600", owner)
		meta(&a, "user", in.User)
		meta(&a, "fingerprint", fp)
		return a, nil
	},
}

var keyRemove = tool{
	name: "key_remove", tier: plan.Change,
	desc: "Remove SSH public keys from a user's authorized_keys, matched by fingerprint (SHA256:...) or by comment. " +
		"Runs under a lockout guard; policy refuses to remove the login user's last key.",
	schema: `{"type":"object","properties":{
		"user":{"type":"string"},
		"match":{"type":"string","description":"SHA256:... fingerprint, or exact key comment"}},
		"required":["user","match"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ User, Match string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := checkUser(in.User); err != nil {
			return plan.Action{}, err
		}
		if strings.TrimSpace(in.Match) == "" {
			return plan.Action{}, errors.New("match is required")
		}
		u, exists, err := lookupUser(ctx, h, in.User)
		if err != nil {
			return plan.Action{}, err
		}
		if !exists {
			return plan.Action{}, fmt.Errorf("no user %s", in.User)
		}
		e, err := readForEdit(ctx, h, authorizedKeys(u))
		if err != nil {
			return plan.Action{}, err
		}
		var kept []string
		removed, remaining := 0, 0
		for _, l := range strings.Split(strings.TrimSuffix(string(e.before), "\n"), "\n") {
			k, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
			if err == nil && (ssh.FingerprintSHA256(k) == in.Match || comment == in.Match) {
				removed++
				continue
			}
			if err == nil {
				remaining++
			}
			kept = append(kept, l)
		}
		if removed == 0 {
			return plan.Action{}, fmt.Errorf("no key in %s matches %q", authorizedKeys(u), in.Match)
		}
		content := strings.Join(kept, "\n")
		if content != "" {
			content += "\n"
		}
		a := plan.Action{Summary: fmt.Sprintf("remove %d key(s) matching %s from %s", removed, in.Match, in.User), Risk: []plan.Risk{plan.RiskLockout}}
		e.write(&a, content, "0600", "")
		meta(&a, "user", in.User)
		meta(&a, "login_user", h.Facts.User)
		meta(&a, "remaining_keys", strconv.Itoa(remaining))
		return a, nil
	},
}

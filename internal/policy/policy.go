// Package policy decides, in code, whether each planned action may run. It is
// evaluated before approval and again right before execution, and the most
// restrictive decision wins. Prompts never carry policy. See specs/plan.md §5.9.
package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/ThembinkosiThemba/vio/internal/plan"
)

// Decision is a rule's verdict. Higher is more restrictive.
type Decision int

const (
	Allow Decision = iota
	Confirm
	Deny
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Confirm:
		return "confirm"
	case Deny:
		return "deny"
	}
	return "unknown"
}

// Context is what rules may consider besides the action itself.
type Context struct {
	Plan        *plan.Plan          // the whole plan, for rules that span actions
	HostTags    map[string][]string // inventory tags per host
	MaxTier     plan.Tier           // ceiling for this run
	AutoApprove bool                // --yes
	AuthMethod  string              // how vio authenticated: "publickey" (vio never uses passwords)
}

// Rule is one policy check.
type Rule interface {
	ID() string
	Evaluate(c Context, a plan.Action) (Decision, string)
}

// Reason is one rule's non-allow verdict.
type Reason struct {
	Rule     string   `json:"rule"`
	Decision Decision `json:"-"`
	Verdict  string   `json:"decision"`
	Msg      string   `json:"msg"`
}

// Result is the combined verdict for one action.
type Result struct {
	Decision Decision
	Reasons  []Reason
}

// Engine evaluates a fixed rule set.
type Engine struct{ rules []Rule }

// New returns an engine with the built-in rules plus extra (user) rules.
func New(extra ...Rule) *Engine {
	return &Engine{rules: append(Builtin(), extra...)}
}

// Evaluate runs every rule against a.
func (e *Engine) Evaluate(c Context, a plan.Action) Result {
	var r Result
	for _, rule := range e.rules {
		d, msg := rule.Evaluate(c, a)
		if d == Allow {
			continue
		}
		r.Reasons = append(r.Reasons, Reason{Rule: rule.ID(), Decision: d, Verdict: d.String(), Msg: msg})
		r.Decision = max(r.Decision, d)
	}
	return r
}

// EvaluatePlan evaluates every action. The overall decision is the most restrictive.
func (e *Engine) EvaluatePlan(c Context, p *plan.Plan) (Decision, map[string]Result) {
	c.Plan = p
	out := map[string]Result{}
	worst := Allow
	for _, a := range p.Actions {
		r := e.Evaluate(c, a)
		out[a.ID] = r
		worst = max(worst, r.Decision)
	}
	return worst, out
}

// ruleFunc adapts a function to Rule.
type ruleFunc struct {
	id string
	fn func(Context, plan.Action) (Decision, string)
}

func (r ruleFunc) ID() string                                           { return r.id }
func (r ruleFunc) Evaluate(c Context, a plan.Action) (Decision, string) { return r.fn(c, a) }

// Builtin returns vio's default rules.
func Builtin() []Rule {
	return []Rule{
		ruleFunc{"tier-ceiling", tierCeiling},
		ruleFunc{"ssh-port-firewall", sshPortFirewall},
		ruleFunc{"operator-account", operatorAccount},
		ruleFunc{"sshd-keep-access", sshdKeepAccess},
		ruleFunc{"protected-paths", protectedPaths},
		ruleFunc{"fs-remove-paths", fsRemovePaths},
		ruleFunc{"confirm-dangerous", confirmDangerous},
		ruleFunc{"confirm-tainted", confirmTainted},
		ruleFunc{"confirm-prod-autoapprove", confirmProdAuto},
	}
}

func tierCeiling(c Context, a plan.Action) (Decision, string) {
	if a.Tier > c.MaxTier {
		return Deny, fmt.Sprintf("%s is a %s-tier tool; this run allows up to %s (max_tier)", a.Tool, a.Tier, c.MaxTier)
	}
	return Allow, ""
}

// sshPortFirewall blocks firewall changes that would cut off the operator's
// SSH port, unless an earlier action in the same plan allows it.
func sshPortFirewall(c Context, a plan.Action) (Decision, string) {
	port := a.Meta["ssh_port"]
	switch a.Tool {
	case "fw_deny":
		if a.Meta["port"] == port && (a.Meta["from"] == "" || a.Meta["from"] == "any") {
			return Deny, "this would block the SSH port (" + port + ") you are connected on"
		}
	case "fw_enable", "fw_default_deny":
		if a.Meta["ssh_allowed"] == "true" || allowedEarlier(c.Plan, a, port) {
			return Allow, ""
		}
		return Deny, "SSH port " + port + " is not allowed by the firewall rules; add fw_allow port " + port + " earlier in the same plan"
	}
	return Allow, ""
}

func allowedEarlier(p *plan.Plan, a plan.Action, port string) bool {
	if p == nil {
		return false
	}
	for _, b := range p.Actions {
		if b.ID == a.ID {
			return false
		}
		if b.Host == a.Host && b.Tool == "fw_allow" && b.Meta["port"] == port && (b.Meta["from"] == "" || b.Meta["from"] == "any") {
			return true
		}
	}
	return false
}

func operatorAccount(_ Context, a plan.Action) (Decision, string) {
	login := a.Meta["login_user"]
	if login == "" || a.Meta["user"] != login {
		return Allow, ""
	}
	switch a.Tool {
	case "user_lock", "user_remove":
		return Deny, login + " is the account vio logs in with"
	case "key_remove":
		if a.Meta["remaining_keys"] == "0" {
			return Deny, "this would remove the last SSH key of " + login + ", the account vio logs in with"
		}
	}
	return Allow, ""
}

func sshdKeepAccess(c Context, a plan.Action) (Decision, string) {
	if a.Tool != "sshd_set" {
		return Allow, ""
	}
	login := a.Meta["login_user"]
	if v := a.Meta["sshd.permitrootlogin"]; login == "root" && v == "no" {
		return Deny, "vio logs in as root; use PermitRootLogin prohibit-password, or log in as another user first"
	}
	if a.Meta["sshd.pubkeyauthentication"] == "no" {
		return Deny, "disabling public key authentication would lock out key-based access"
	}
	if a.Meta["sshd.passwordauthentication"] == "no" && c.AuthMethod == "password" {
		return Deny, "you authenticated with a password; add a key first"
	}
	if v, ok := a.Meta["sshd.allowusers"]; ok && !slices.Contains(strings.Fields(v), login) {
		return Deny, "AllowUsers must include " + login + ", the account vio logs in with"
	}
	return Allow, ""
}

var protected = []string{"/boot/", "/etc/fstab", "/etc/default/grub", "/etc/grub.d/", "/etc/passwd", "/etc/group",
	"/etc/shadow", "/etc/gshadow", "/etc/crypttab", "/etc/kernel/", "/etc/initramfs-tools/"}

func protectedPaths(_ Context, a plan.Action) (Decision, string) {
	for _, s := range a.Steps {
		if s.Kind != "write" {
			continue
		}
		for _, p := range protected {
			if s.Path == strings.TrimSuffix(p, "/") || strings.HasPrefix(s.Path, p) {
				return Deny, s.Path + " affects boot or accounts and is not edited by vio"
			}
		}
	}
	return Allow, ""
}

var removable = []string{"/tmp/", "/var/tmp/", "/var/log/", "/var/cache/"}

func fsRemovePaths(_ Context, a plan.Action) (Decision, string) {
	if a.Tool != "fs_remove" {
		return Allow, ""
	}
	p := a.Meta["path"]
	for _, ok := range removable {
		if strings.HasPrefix(p, ok) && len(p) > len(ok) {
			return Allow, ""
		}
	}
	return Deny, "fs_remove is limited to paths under " + strings.Join(removable, ", ")
}

func confirmDangerous(_ Context, a plan.Action) (Decision, string) {
	switch {
	case a.Tier == plan.Dangerous:
		return Confirm, "dangerous-tier tool"
	case a.Has(plan.RiskIrreversible):
		return Confirm, "cannot be rolled back"
	}
	return Allow, ""
}

func confirmTainted(_ Context, a plan.Action) (Decision, string) {
	if len(a.Taint) == 0 {
		return Allow, ""
	}
	var parts []string
	for _, t := range a.Taint {
		parts = append(parts, fmt.Sprintf("%s=%q came from %s", t.Arg, t.Value, t.Source))
	}
	return Confirm, "arguments taken from host data, not from you: " + strings.Join(parts, "; ")
}

func confirmProdAuto(c Context, a plan.Action) (Decision, string) {
	if c.AutoApprove && slices.Contains(c.HostTags[a.Host], "prod") {
		return Confirm, a.Host + " is tagged prod, so --yes does not apply"
	}
	return Allow, ""
}

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"

	"go.yaml.in/yaml/v3"

	"github.com/ThembinkosiThemba/vio/internal/plan"
)

// File is policy.yaml: operator rules layered on top of the built-in ones.
// User rules can deny or require confirmation; they can never allow something
// a built-in rule restricts, because the most restrictive decision wins.
type File struct {
	Rules []UserRule `yaml:"rules"`
}

// UserRule matches actions by tool, host, tag, tier and risk. Every field that
// is set must match (AND); within a field any value may match (OR). Tool and
// host values are globs, e.g. "pkg_*" or "web-*".
type UserRule struct {
	RuleID   string   `yaml:"id"`
	Decision string   `yaml:"decision"` // deny | confirm
	Tools    []string `yaml:"tools"`
	Hosts    []string `yaml:"hosts"`
	Tags     []string `yaml:"tags"`
	Tiers    []string `yaml:"tiers"`
	Risks    []string `yaml:"risks"`
	Message  string   `yaml:"message"`

	decision Decision
	host     map[string][]string
}

// ID implements Rule.
func (r *UserRule) ID() string { return "user:" + r.RuleID }

// Evaluate implements Rule.
func (r *UserRule) Evaluate(c Context, a plan.Action) (Decision, string) {
	if !globAny(r.Tools, a.Tool) || !globAny(r.Hosts, a.Host) {
		return Allow, ""
	}
	if len(r.Tags) > 0 && !slices.ContainsFunc(r.Tags, func(t string) bool { return slices.Contains(c.HostTags[a.Host], t) }) {
		return Allow, ""
	}
	if len(r.Tiers) > 0 && !slices.Contains(r.Tiers, a.Tier.String()) {
		return Allow, ""
	}
	if len(r.Risks) > 0 && !slices.ContainsFunc(r.Risks, func(k string) bool { return a.Has(plan.Risk(k)) }) {
		return Allow, ""
	}
	msg := r.Message
	if msg == "" {
		msg = "matched policy.yaml rule " + r.RuleID
	}
	return r.decision, msg
}

func globAny(patterns []string, s string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if ok, _ := path.Match(p, s); ok {
			return true
		}
	}
	return false
}

// Load reads policy.yaml. A missing file means no user rules.
func Load(file string) ([]Rule, error) {
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses policy.yaml content.
func Parse(data []byte) ([]Rule, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("policy.yaml: %w", err)
	}
	var out []Rule
	for i := range f.Rules {
		r := &f.Rules[i]
		if r.RuleID == "" {
			return nil, fmt.Errorf("policy.yaml: rule %d needs an id", i+1)
		}
		switch r.Decision {
		case "deny":
			r.decision = Deny
		case "confirm":
			r.decision = Confirm
		default:
			return nil, fmt.Errorf("policy.yaml: rule %s: decision must be deny or confirm (user rules can only restrict)", r.RuleID)
		}
		for _, p := range append(slices.Clone(r.Tools), r.Hosts...) {
			if _, err := path.Match(p, ""); err != nil {
				return nil, fmt.Errorf("policy.yaml: rule %s: bad pattern %q", r.RuleID, p)
			}
		}
		for _, t := range r.Tiers {
			if _, err := plan.ParseTier(t); err != nil {
				return nil, fmt.Errorf("policy.yaml: rule %s: %w", r.RuleID, err)
			}
		}
		out = append(out, r)
	}
	return out, nil
}

// Skeleton is the commented policy.yaml written by `vio init`.
const Skeleton = `# vio policy: rules added on top of vio's built-in safety rules.
# User rules can only restrict (deny or confirm); they cannot allow anything a
# built-in rule blocks. Every field set on a rule must match.
#
# rules:
#   - id: no-reboots-in-prod
#     decision: deny            # deny | confirm
#     tools: [host_reboot]      # globs, e.g. "pkg_*"
#     tags: [prod]              # inventory tags
#     message: Reboot prod hosts in a maintenance window, by hand.
#   - id: review-package-changes
#     decision: confirm
#     tools: ["pkg_*"]
#     hosts: ["db-*"]
#     risks: [downtime]         # lockout | downtime | data_loss | irreversible
#     tiers: [change]           # observe | change | dangerous
rules: []
`

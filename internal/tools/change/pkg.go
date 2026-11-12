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

// installed returns name → version for those of names that are installed.
func installed(ctx context.Context, h *tools.Host, pm adapters.Pkg, names ...string) (map[string]string, error) {
	if len(names) == 0 {
		return map[string]string{}, nil
	}
	// Query exits non-zero when some packages are missing; the output is still valid.
	res, err := h.Run(ctx, true, pm.Query(names...)...)
	if err != nil {
		return nil, err
	}
	return adapters.ParseQuery(string(res.Stdout)), nil
}

func pkgNames(in []string) error {
	if len(in) == 0 {
		return errors.New("names is required")
	}
	for _, n := range in {
		if err := checkName("package", n); err != nil {
			return err
		}
	}
	return nil
}

// planInstall adds steps that install whichever of names are missing, with a
// rollback that removes only those. It returns the newly installed names.
func planInstall(ctx context.Context, h *tools.Host, a *plan.Action, names ...string) ([]string, error) {
	pm, err := adapters.PkgFor(h.Facts)
	if err != nil {
		return nil, err
	}
	have, err := installed(ctx, h, pm, names...)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, n := range names {
		if _, ok := have[n]; !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 {
		return nil, nil
	}
	if r := pm.Refresh(); r != nil {
		a.Steps = append(a.Steps, plan.Run("refresh package index", r...))
	}
	a.Steps = append(a.Steps, plan.Run("install "+strings.Join(missing, " "), pm.Install(missing...)...))
	rb := rollback(a)
	rb.Commands = append(rb.Commands, pm.Remove(missing...))
	for _, n := range missing {
		a.Verify = append(a.Verify, plan.Probe{Kind: plan.ProbeCmd, Desc: n + " is installed", Args: pm.Query(n), Want: n})
	}
	return missing, nil
}

var pkgInstall = tool{
	name: "pkg_install", tier: plan.Change,
	desc:   "Install packages with the host's package manager. Rollback removes the ones this action installed.",
	schema: `{"type":"object","properties":{"names":{"type":"array","items":{"type":"string"}}},"required":["names"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ Names []string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := pkgNames(in.Names); err != nil {
			return plan.Action{}, err
		}
		var a plan.Action
		missing, err := planInstall(ctx, h, &a, in.Names...)
		if err != nil {
			return a, err
		}
		if len(missing) == 0 {
			return a, errors.New("all of these packages are already installed")
		}
		a.Summary = "install " + strings.Join(missing, ", ")
		return a, nil
	},
}

var pkgUpgrade = tool{
	name: "pkg_upgrade", tier: plan.Change,
	desc: "Upgrade packages to the versions in the last package index refresh: the named ones, all pending, or (security) security updates only. " +
		"Rollback reinstalls the previous versions where the repository still has them.",
	schema: `{"type":"object","properties":{
		"names":{"type":"array","items":{"type":"string"},"description":"Empty means every pending upgrade"},
		"security":{"type":"boolean","description":"Only security updates"}}}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct {
			Names    []string
			Security bool
		}
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		for _, n := range in.Names {
			if err := checkName("package", n); err != nil {
				return plan.Action{}, err
			}
		}
		pm, err := adapters.PkgFor(h.Facts)
		if err != nil {
			return plan.Action{}, err
		}
		res, err := h.Run(ctx, true, pm.Upgradable(in.Security)...)
		if err != nil {
			return plan.Action{}, err
		}
		out := string(res.Stdout)
		if in.Security && pm.Name() == "apt" {
			var keep []string
			for _, line := range strings.Split(out, "\n") {
				if adapters.AptSecurity(line) {
					keep = append(keep, line)
				}
			}
			out = strings.Join(keep, "\n")
		}
		ups := pm.ParseUpgradable(out)
		if len(in.Names) > 0 {
			ups = slices.DeleteFunc(ups, func(u adapters.Upgrade) bool { return !slices.Contains(in.Names, u.Name) })
		}
		if len(ups) == 0 {
			return plan.Action{}, errors.New("no matching upgrades are pending (the package index may need a refresh: apt-get update / dnf makecache)")
		}
		names := make([]string, len(ups))
		for i, u := range ups {
			names[i] = u.Name
		}
		old, err := installed(ctx, h, pm, names...)
		if err != nil {
			return plan.Action{}, err
		}
		var diff strings.Builder
		for _, u := range ups {
			fmt.Fprintf(&diff, "  %s %s → %s\n", u.Name, old[u.Name], u.To)
		}
		kind := "packages"
		if in.Security {
			kind = "security updates"
		}
		a := plan.Action{
			Summary: fmt.Sprintf("upgrade %d %s", len(ups), kind),
			Diff:    diff.String(),
			Steps:   []plan.Step{plan.Run("upgrade "+strings.Join(names, " "), pm.Upgrade(names...)...)},
			Risk:    []plan.Risk{plan.RiskDowntime},
		}
		if len(old) > 0 {
			a.Rollback = &plan.RollbackSpec{Commands: [][]string{pm.InstallExact(old)}}
		} else {
			a.AddRisk(plan.RiskIrreversible)
		}
		meta(&a, "packages", strings.Join(names, ","))
		return a, nil
	},
}

var pkgRemove = tool{
	name: "pkg_remove", tier: plan.Dangerous,
	desc:   "Remove packages. Configuration files are kept. Rollback reinstalls the same versions if the repository still has them.",
	schema: `{"type":"object","properties":{"names":{"type":"array","items":{"type":"string"}}},"required":["names"]}`,
	plan: func(ctx context.Context, h *tools.Host, raw json.RawMessage) (plan.Action, error) {
		var in struct{ Names []string }
		if err := tools.Decode(raw, &in); err != nil {
			return plan.Action{}, err
		}
		if err := pkgNames(in.Names); err != nil {
			return plan.Action{}, err
		}
		pm, err := adapters.PkgFor(h.Facts)
		if err != nil {
			return plan.Action{}, err
		}
		have, err := installed(ctx, h, pm, in.Names...)
		if err != nil {
			return plan.Action{}, err
		}
		if len(have) == 0 {
			return plan.Action{}, errors.New("none of these packages are installed")
		}
		names := slices.Sorted(maps.Keys(have))
		a := plan.Action{
			Summary:  "remove " + strings.Join(names, ", "),
			Steps:    []plan.Step{plan.Run("remove "+strings.Join(names, " "), pm.Remove(names...)...)},
			Rollback: &plan.RollbackSpec{Commands: [][]string{pm.InstallExact(have)}},
			Risk:     []plan.Risk{plan.RiskDowntime},
		}
		for _, n := range names {
			if n == "openssh-server" || n == "sudo" || n == "openssh" {
				a.AddRisk(plan.RiskLockout)
			}
		}
		meta(&a, "packages", strings.Join(names, ","))
		return a, nil
	},
}

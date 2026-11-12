package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/user"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ThembinkosiThemba/vio/internal/agent"
	"github.com/ThembinkosiThemba/vio/internal/apply"
	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/checks"
	"github.com/ThembinkosiThemba/vio/internal/config"
	"github.com/ThembinkosiThemba/vio/internal/facts"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/policy"
	"github.com/ThembinkosiThemba/vio/internal/redact"
	"github.com/ThembinkosiThemba/vio/internal/runbooks"
	"github.com/ThembinkosiThemba/vio/internal/tools"
)

// agentOptions builds session options from config. tier overrides max_tier
// when non-empty, but never raises it above the config ceiling.
func (a *app) agentOptions(cfg config.Config, tier string) (agent.Options, error) {
	max, err := plan.ParseTier(cfg.MaxTier)
	if err != nil {
		return agent.Options{}, err
	}
	if tier != "" {
		t, err := plan.ParseTier(tier)
		if err != nil {
			return agent.Options{}, &usageError{err.Error()}
		}
		if t > max {
			return agent.Options{}, fmt.Errorf("--max-tier %s is above max_tier %s in %s", t, max, a.paths.ConfigFile())
		}
		max = t
	}
	rules, err := policy.Load(a.paths.PolicyFile())
	if err != nil {
		return agent.Options{}, err
	}
	rbs, err := runbooks.Load(a.paths.RunbooksDir())
	if err != nil {
		return agent.Options{}, err
	}
	op := "operator"
	if u, err := user.Current(); err == nil {
		op = u.Username
	}
	return agent.Options{
		MaxSteps:    cfg.Budget.MaxTurns,
		MaxTier:     max,
		Policy:      policy.New(rules...),
		GuardWindow: cfg.GuardWindow,
		StateDir:    a.paths.StateDir,
		Operator:    op,
		Runbooks:    rbs,
	}, nil
}

// modeLabel describes what the agent may do, for the banner and footer.
func modeLabel(t plan.Tier) string {
	switch t {
	case plan.Observe:
		return "read-only"
	case plan.Change:
		return "changes need approval"
	}
	return "all tools · approval required"
}

// ReviewPlan renders a plan with its policy verdicts and asks for approval.
func (u *termUI) ReviewPlan(p *plan.Plan, verdicts map[string]policy.Result) bool {
	worst := u.renderPlan(p, verdicts)
	if worst == policy.Deny {
		fmt.Fprintf(u.w, "  %s\n\n", sErr.Render("✗ Policy denies this plan, so it can't be applied."))
		return false
	}
	q := fmt.Sprintf("Apply plan %s?", p.ID)
	var detail []string
	if worst == policy.Confirm {
		detail = append(detail, "Some actions need your explicit confirmation (see above).")
	}
	if slices.Contains(p.Risks(), plan.RiskLockout) {
		detail = append(detail, "Access-affecting steps run under a guard: if a fresh SSH login fails, the host reverts itself.")
	}
	return u.a.confirm(q, detail...)
}

// renderPlan prints a plan and returns its most restrictive verdict.
func (u *termUI) renderPlan(p *plan.Plan, verdicts map[string]policy.Result) policy.Decision {
	u.pause()
	u.mu.Lock()
	w := u.w
	worst := policy.Allow
	for _, r := range verdicts {
		worst = max(worst, r.Decision)
	}
	risks := make([]string, 0)
	for _, r := range p.Risks() {
		risks = append(risks, string(r))
	}
	head := fmt.Sprintf("plan %s · %d action", p.ID, len(p.Actions))
	if len(p.Actions) != 1 {
		head += "s"
	}
	head += " · " + strings.Join(p.Hosts, ", ")
	if len(risks) > 0 {
		head += " · risk: " + strings.Join(risks, ", ")
	}
	fmt.Fprintf(w, "\n  %s\n", sBold.Render(head))
	for i, a := range p.Actions {
		var tags []string
		tags = append(tags, a.Tier.String())
		if a.Has(plan.RiskLockout) {
			tags = append(tags, "guard "+roundDuration(u.guard()))
		}
		if a.Rollback.Empty() {
			tags = append(tags, sWarn.Render("no rollback"))
		} else {
			tags = append(tags, "rollback ✓")
		}
		fmt.Fprintf(w, "  %s  %s  %s  %s\n", sAccent.Render(fmt.Sprint(i+1)), sMuted.Render(a.Host), a.Summary, sFaint.Render(strings.Join(tags, " · ")))
		for _, line := range diffLines(a.Diff, 30) {
			fmt.Fprintf(w, "       %s\n", line)
		}
		for _, r := range verdicts[a.ID].Reasons {
			style := sWarn
			if r.Decision == policy.Deny {
				style = sErr
			}
			fmt.Fprintf(w, "       %s %s\n", style.Render(r.Verdict+":"), r.Msg)
		}
	}
	fmt.Fprintf(w, "  %s\n", sFaint.Render("hash "+p.Hash[:16]+"…"))
	u.mu.Unlock()
	return worst
}

// guard returns the configured guard window for display.
func (u *termUI) guard() time.Duration {
	if u.guardWindow > 0 {
		return u.guardWindow
	}
	return 120 * time.Second
}

func diffLines(diff string, max int) []string {
	if diff == "" {
		return nil
	}
	lines := strings.Split(strings.TrimRight(redact.String(diff), "\n"), "\n")
	var out []string
	for i, l := range lines {
		if i == max {
			out = append(out, sFaint.Render(fmt.Sprintf("… %d more lines", len(lines)-max)))
			break
		}
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
			out = append(out, sFaint.Render(l))
		case strings.HasPrefix(l, "+"):
			out = append(out, sAccent.Render(l))
		case strings.HasPrefix(l, "-"):
			out = append(out, sErr.Render(l))
		default:
			out = append(out, sMuted.Render(l))
		}
	}
	return out
}

// Progress prints apply engine events.
func (u *termUI) Progress(e apply.Event) {
	u.pause()
	u.mu.Lock()
	defer u.mu.Unlock()
	host, id := "", ""
	if e.Action != nil {
		host, id = e.Action.Host, e.Action.ID
	}
	switch e.Phase {
	case "start":
		fmt.Fprintf(u.w, "  %s %s  %s %s\n", sFaint.Render("○"), sMuted.Render(host), sFaint.Render(id), e.Msg)
	case "done":
		fmt.Fprintf(u.w, "  %s %s  %s %s\n", sAccent.Render("✓"), sMuted.Render(host), sFaint.Render(id), e.Msg)
	case "failed":
		fmt.Fprintf(u.w, "  %s %s  %s %s\n", sErr.Render("✗"), sMuted.Render(host), sFaint.Render(id), e.Msg)
	case "rollback", "wait", "reverted":
		fmt.Fprintf(u.w, "    %s\n", sWarn.Render(e.Msg))
	default:
		fmt.Fprintf(u.w, "    %s\n", sFaint.Render(e.Msg))
	}
}

// session opens an agent session without a model, for commands that plan
// or apply without the LLM.
func (a *app) session(ui *termUI, tier string) (*agent.Session, config.Config, error) {
	if err := a.ensureDirs(); err != nil {
		return nil, config.Config{}, err
	}
	cfg, err := config.Load(a.paths.ConfigFile())
	if err != nil {
		return nil, cfg, err
	}
	opts, err := a.agentOptions(cfg, tier)
	if err != nil {
		return nil, cfg, err
	}
	ui.guardWindow = cfg.GuardWindow
	s, err := agent.New(nil, a.agentEnv(), ui, opts)
	return s, cfg, err
}

// reviewAndApply asks for approval (unless --yes covers it) and applies p.
func (a *app) reviewAndApply(ctx context.Context, s *agent.Session, ui *termUI, p *plan.Plan, yes, atomic bool) error {
	pc := s.PolicyContext()
	pc.AutoApprove = yes
	e := s.ApplyEnv()
	worst, verdicts := e.Policy.EvaluatePlan(pc, p)
	pre := p.Approval != nil
	switch {
	case worst == policy.Deny:
		ui.ReviewPlan(p, verdicts)
		return &exitErr{exitPolicy, errors.New("policy denied the plan")}
	case pre:
		// Approved earlier (e.g. by a second operator with `vio apply --approve-only`);
		// CheckIntegrity in Load already bound the approval to this exact hash.
		fmt.Fprintf(a.stdout, "  %s\n", sMuted.Render(fmt.Sprintf("plan %s was approved by %s at %s", p.ID, p.Approval.Operator, p.Approval.At.Format(time.RFC3339))))
	case yes && worst == policy.Allow && p.MaxTier() <= plan.Change:
		fmt.Fprintf(a.stdout, "  %s\n", sMuted.Render("plan "+p.ID+" auto-approved (--yes)"))
	default:
		if !ui.ReviewPlan(p, verdicts) {
			_ = a.record(audit.Record{Kind: audit.KindApprove, Tool: "plan", Msg: p.ID + " declined"})
			return &exitErr{exitDeclined, errors.New("plan not approved; nothing was changed")}
		}
	}
	if !pre {
		if err := p.Approve(s.Operator(), s.MaxTier()); err != nil {
			return err
		}
	}
	if err := a.record(audit.Record{Kind: audit.KindApprove, Tool: "plan", Msg: p.ID + " approved, hash " + p.Hash}); err != nil {
		return err
	}
	e.Atomic = atomic
	e.PolicyCtx = pc
	rep, err := apply.Apply(ctx, e, p)
	if err != nil {
		return err
	}
	applied := 0
	for _, o := range rep.Outcomes {
		if o.Status == "applied" {
			applied++
		}
	}
	if rep.Code == apply.CodeOK {
		fmt.Fprintf(a.stdout, "  %s applied %s · %d action(s) · undo with: vio rollback %s\n", sAccent.Render("✓"), p.ID, applied, rep.ID)
		return nil
	}
	fmt.Fprintf(a.stdout, "  %s %s: %d of %d applied (apply id %s)\n", sErr.Render("✗"), p.ID, applied, len(p.Actions), rep.ID)
	codes := map[int]int{apply.CodePolicy: exitPolicy, apply.CodeDrift: exitDrift, apply.CodeReverted: exitRevert}
	code, ok := codes[rep.Code]
	if !ok {
		code = exitError
	}
	return &exitErr{code, fmt.Errorf("apply %s did not complete", rep.ID)}
}

// cmdCheck runs the security baseline, with no model.
func (a *app) cmdCheck(ctx context.Context, args []string) error {
	fs := a.newFlags("check", "check [host|group ...] [--fix] [-o plan.json] [--json] [--fail-on high] [--yes]")
	fix := fs.Bool("fix", false, "propose a plan that fixes the findings")
	out := fs.String("o", "", "with --fix: write the plan to this file instead of applying it")
	asJSON := fs.Bool("json", false, "print findings as JSON lines")
	failOn := fs.String("fail-on", "high", "exit 1 if a finding at or above this severity fails (info|low|medium|high|critical|none)")
	yes := fs.Bool("yes", false, "with --fix: approve without asking when policy allows")
	atomic := fs.Bool("atomic", false, "with --fix: roll back everything if any action fails")
	tier := fs.String("max-tier", "", "highest tool tier for fixes (observe|change|dangerous)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	threshold := map[string]checks.Severity{"info": checks.Info, "low": checks.Low, "medium": checks.Medium, "high": checks.High, "critical": checks.Critical}
	limit, ok := threshold[*failOn]
	if !ok && *failOn != "none" {
		return usagef("check: --fail-on must be info, low, medium, high, critical or none")
	}
	inv, err := a.loadInventory()
	if err != nil {
		return err
	}
	hosts, err := inv.Resolve(pos...)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("no hosts in inventory")
	}

	results := a.runChecks(ctx, hosts)
	failing := false
	for _, r := range results {
		if err := a.printFindings(r, *asJSON); err != nil {
			return err
		}
		for _, f := range r.findings {
			if f.Status == checks.Fail && ok && f.Severity >= limit {
				failing = true
			}
		}
	}
	if !*fix {
		if failing {
			return &exitErr{exitError, fmt.Errorf("failing findings at or above %s", *failOn)}
		}
		return nil
	}

	ui := newTermUI(a)
	a.pauseHook = ui.pause
	s, _, err := a.session(ui, *tier)
	if err != nil {
		return err
	}
	defer s.Close()
	var actions []plan.Action
	for _, r := range results {
		if r.err != nil {
			continue
		}
		h, err := s.Host(ctx, r.host.Name)
		if err != nil {
			return err
		}
		for _, fx := range checks.Fixes(h, r.findings) {
			t, _ := agent.Registry().Get(fx.Tool)
			ct, ok := t.(tools.ChangeTool)
			if !ok || t.Tier() > s.MaxTier() {
				fmt.Fprintf(a.stdout, "  %s %s: %s needs max tier %s\n", sFaint.Render("-"), r.host.Name, fx.Tool, t.Tier())
				continue
			}
			act, err := ct.Plan(ctx, h, fx.Args)
			if err != nil {
				fmt.Fprintf(a.stdout, "  %s %s: %v\n", sFaint.Render("-"), r.host.Name, err)
				continue
			}
			actions = append(actions, act)
		}
	}
	if len(actions) == 0 {
		fmt.Fprintln(a.stdout, "nothing to fix automatically")
		return nil
	}
	p, err := plan.New("vio check --fix", actions)
	if err != nil {
		return err
	}
	if *out != "" {
		_, verdicts := s.ApplyEnv().Policy.EvaluatePlan(s.PolicyContext(), p)
		ui.renderPlan(p, verdicts)
		if err := p.Save(*out); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "wrote %s · apply with: vio apply %s\n", *out, *out)
		return nil
	}
	return a.reviewAndApply(ctx, s, ui, p, *yes, *atomic)
}

type hostChecks struct {
	host     *inventory.Host
	facts    facts.Facts
	findings []checks.Finding
	err      error
}

// runChecks checks hosts in parallel (up to 8) over their own connections.
func (a *app) runChecks(ctx context.Context, hosts []*inventory.Host) []hostChecks {
	out := make([]hostChecks, len(hosts))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, ih := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := hostChecks{host: ih}
			x, err := a.dial(ctx, ih)
			if err != nil {
				r.err = err
				out[i] = r
				return
			}
			defer x.Close()
			cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			f, err := facts.Gather(cctx, x)
			if err != nil {
				r.err = err
				out[i] = r
				return
			}
			r.facts = f
			r.findings = checks.Run(cctx, &tools.Host{Name: ih.Name, Tags: ih.Tags, X: x, Facts: f})
			out[i] = r
		}()
	}
	wg.Wait()
	for _, r := range out {
		exit := 0
		msg := fmt.Sprintf("%d findings", len(r.findings))
		if r.err != nil {
			exit, msg = 1, r.err.Error()
		}
		_ = a.record(audit.Record{Kind: audit.KindObserve, Tool: "check", Host: r.host.Name, Msg: msg, Exit: &exit})
	}
	return out
}

func (a *app) printFindings(r hostChecks, asJSON bool) error {
	if asJSON {
		type line struct {
			Host     string           `json:"host"`
			System   string           `json:"system,omitempty"`
			Error    string           `json:"error,omitempty"`
			Findings []checks.Finding `json:"findings,omitempty"`
		}
		l := line{Host: r.host.Name, Findings: r.findings}
		if r.err != nil {
			l.Error = redact.String(hint(r.host, r.err))
		} else {
			l.System = r.facts.Summary()
		}
		return json.NewEncoder(a.stdout).Encode(l)
	}
	if r.err != nil {
		fmt.Fprintf(a.stdout, "%s %s  %s\n\n", sErr.Render("✗"), sBold.Render(r.host.Name), hint(r.host, r.err))
		return nil
	}
	fmt.Fprintf(a.stdout, "%s %s  %s\n", sAccent.Render("●"), sBold.Render(r.host.Name), sMuted.Render(r.facts.Summary()))
	for _, f := range r.findings {
		var mark string
		switch f.Status {
		case checks.Pass:
			mark = sAccent.Render("✓")
		case checks.Fail:
			mark = sErr.Render("✗")
		default:
			mark = sFaint.Render("-")
		}
		sev := ""
		if f.Status == checks.Fail {
			sev = f.Severity.String()
		}
		detail := f.Detail
		if f.Status != checks.Fail {
			detail = sFaint.Render(detail)
		}
		fmt.Fprintf(a.stdout, "  %s %-8s %s  %s  %s\n", mark, sev, sFaint.Render(f.ID), f.Title, detail)
	}
	fmt.Fprintln(a.stdout)
	return nil
}

// cmdPlan asks the agent for a plan and writes it to a file, without applying.
func (a *app) cmdPlan(ctx context.Context, args []string) error {
	fs := a.newFlags("plan", `plan "<goal>" [-H host] [-o plan.json]`)
	host := fs.String("H", "", "target host")
	out := fs.String("o", "plan.json", "write the plan here")
	tier := fs.String("max-tier", "", "highest tool tier (change|dangerous)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	goal := strings.TrimSpace(strings.Join(pos, " "))
	if goal == "" {
		return usagef(`plan: expected a goal, e.g. vio plan -H web-1 "install fail2ban for sshd"`)
	}
	ui := newTermUI(a)
	a.pauseHook = ui.pause
	s, cfg, err := a.session(ui, *tier)
	if err != nil {
		return err
	}
	defer s.Close()
	if s.MaxTier() < plan.Change {
		return errors.New("planning changes needs max_tier change or dangerous")
	}
	model, err := a.provider(cfg)
	if err != nil {
		return fmt.Errorf("%w (run `vio setup` to fix)", err)
	}
	s.SetModel(model)
	s.SetMode(agent.ModeCollect)
	msg := goal
	if *host != "" {
		msg += "\n\n(Target server: " + *host + ". Propose the changes; they will be saved to a plan file for review.)"
	}
	if err := a.record(audit.Record{Kind: audit.KindSessionStart, Msg: "plan: " + model.Model() + " via " + model.Name()}); err != nil {
		return err
	}
	ui.begin(time.Now())
	err = s.Send(ctx, msg)
	ui.pause()
	if err != nil && !errors.Is(err, agent.ErrStepLimit) {
		return errors.New(friendlyError(err, cfg))
	}
	p, err := s.TakePlan(goal)
	if err != nil {
		return err
	}
	_, verdicts := s.ApplyEnv().Policy.EvaluatePlan(s.PolicyContext(), p)
	ui.renderPlan(p, verdicts)
	if err := p.Save(*out); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "wrote %s · review it, then: vio apply %s\n", *out, *out)
	return nil
}

// cmdApply applies a plan file.
func (a *app) cmdApply(ctx context.Context, args []string) error {
	fs := a.newFlags("apply", "apply plan.json [--yes] [--atomic] [--approve-only]")
	yes := fs.Bool("yes", false, "approve without asking when policy allows (never dangerous or prod-tagged actions)")
	atomic := fs.Bool("atomic", false, "roll back every applied action if one fails")
	approveOnly := fs.Bool("approve-only", false, "review and record approval in the file without applying (for a second operator)")
	tier := fs.String("max-tier", "", "highest tool tier (change|dangerous)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("apply: expected one plan file")
	}
	p, err := plan.Load(pos[0])
	if errors.Is(err, plan.ErrTampered) {
		return &exitErr{exitPolicy, err}
	}
	if err != nil {
		return err
	}
	ui := newTermUI(a)
	a.pauseHook = ui.pause
	s, _, err := a.session(ui, *tier)
	if err != nil {
		return err
	}
	defer s.Close()
	if *approveOnly {
		worst, verdicts := s.ApplyEnv().Policy.EvaluatePlan(s.PolicyContext(), p)
		if worst == policy.Deny {
			ui.ReviewPlan(p, verdicts)
			return &exitErr{exitPolicy, errors.New("policy denied the plan")}
		}
		if !ui.ReviewPlan(p, verdicts) {
			return &exitErr{exitDeclined, errors.New("not approved")}
		}
		if err := p.Approve(s.Operator(), s.MaxTier()); err != nil {
			return err
		}
		if err := p.Save(pos[0]); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "approved %s (hash %s…) · apply with: vio apply %s\n", p.ID, p.Hash[:16], pos[0])
		return a.record(audit.Record{Kind: audit.KindApprove, Tool: "plan", Msg: p.ID + " approved for later, hash " + p.Hash})
	}
	return a.reviewAndApply(ctx, s, ui, p, *yes, *atomic)
}

// cmdRollback reverts a past apply.
func (a *app) cmdRollback(ctx context.Context, args []string) error {
	fs := a.newFlags("rollback", "rollback <apply-id> [--yes]")
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("rollback: expected an apply id, e.g. vio rollback x-1a2b3c4d")
	}
	rec, err := apply.LoadRecord(a.paths.StateDir, pos[0])
	if err != nil {
		return err
	}
	var todo []string
	for _, o := range rec.Outcomes {
		if o.Status == "applied" {
			for _, act := range rec.Plan.Actions {
				if act.ID == o.ActionID {
					todo = append(todo, act.Host+": "+act.Summary)
				}
			}
		}
	}
	if len(todo) == 0 {
		fmt.Fprintln(a.stdout, "nothing to roll back")
		return nil
	}
	if !*yes && !a.confirm(fmt.Sprintf("Roll back %d change(s) from %s?", len(todo), rec.ID), todo...) {
		return &exitErr{exitDeclined, errors.New("not rolled back")}
	}
	ui := newTermUI(a)
	a.pauseHook = ui.pause
	s, _, err := a.session(ui, "")
	if err != nil {
		return err
	}
	defer s.Close()
	outs, err := apply.Rollback(ctx, s.ApplyEnv(), rec)
	fmt.Fprintf(a.stdout, "rolled back %d action(s) from %s\n", len(outs), rec.ID)
	return err
}

// cmdWatch re-runs the baseline on a schedule and reports changes.
func (a *app) cmdWatch(ctx context.Context, args []string) error {
	fs := a.newFlags("watch", "watch [host|group ...] [--every 1h] [--webhook URL] [--once]")
	every := fs.Duration("every", time.Hour, "how often to check")
	webhook := fs.String("webhook", "", "POST changes as JSON to this URL")
	once := fs.Bool("once", false, "check once, report, and exit")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if *every < time.Minute {
		return usagef("watch: --every must be at least 1m")
	}
	inv, err := a.loadInventory()
	if err != nil {
		return err
	}
	hosts, err := inv.Resolve(pos...)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("no hosts in inventory")
	}
	prev := map[string]map[string]checks.Finding{}
	for {
		for _, r := range a.runChecks(ctx, hosts) {
			now := map[string]checks.Finding{}
			for _, f := range r.findings {
				if f.Status == checks.Fail {
					now[f.ID] = f
				}
			}
			var added, resolved []checks.Finding
			for id, f := range now {
				if _, ok := prev[r.host.Name][id]; !ok {
					added = append(added, f)
				}
			}
			for id, f := range prev[r.host.Name] {
				if _, ok := now[id]; !ok {
					resolved = append(resolved, f)
				}
			}
			prev[r.host.Name] = now
			ts := time.Now().Format("2006-01-02 15:04")
			if r.err != nil {
				fmt.Fprintf(a.stdout, "%s %s unreachable: %s\n", ts, r.host.Name, hint(r.host, r.err))
			}
			for _, f := range added {
				fmt.Fprintf(a.stdout, "%s %s %s %s %s: %s\n", ts, r.host.Name, sErr.Render("✗ new"), f.ID, f.Severity, f.Detail)
			}
			for _, f := range resolved {
				fmt.Fprintf(a.stdout, "%s %s %s %s\n", ts, r.host.Name, sAccent.Render("✓ resolved"), f.ID)
			}
			if *webhook != "" && (len(added) > 0 || len(resolved) > 0 || r.err != nil) {
				if err := postWebhook(ctx, *webhook, r, added, resolved); err != nil {
					fmt.Fprintf(a.stderr, "vio: webhook: %v\n", err)
				}
			}
		}
		if *once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(*every):
		}
	}
}

func postWebhook(ctx context.Context, url string, r hostChecks, added, resolved []checks.Finding) error {
	body := map[string]any{"host": r.host.Name, "new": added, "resolved": resolved, "at": time.Now().UTC()}
	if r.err != nil {
		body["error"] = redact.String(r.err.Error())
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader([]byte(redact.String(string(b)))))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vio-watch")
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %s", url, resp.Status)
	}
	return nil
}

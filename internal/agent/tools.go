package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/facts"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/llm"
	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/policy"
	"github.com/ThembinkosiThemba/vio/internal/redact"
	"github.com/ThembinkosiThemba/vio/internal/tools"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

// sessionTools are handled by the session itself rather than on a host.
var sessionTools = []llm.Tool{
	{
		Name:        "add_host",
		Description: "Add a server to the operator's inventory. The operator is asked to confirm.",
		Schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"name": {"type": "string", "description": "Short lowercase name, e.g. web-1"},
				"addr": {"type": "string", "description": "IP address or DNS name"},
				"user": {"type": "string", "description": "SSH login user"},
				"port": {"type": "integer", "description": "SSH port, default 22"},
				"identity": {"type": "string", "description": "Path to a private key file on the operator's machine, if not using ssh-agent"},
				"tags": {"type": "array", "items": {"type": "string"}},
				"notes": {"type": "string", "description": "Context the operator gave about this server"}
			},
			"required": ["name", "addr", "user"]
		}`),
	},
	{
		Name:        "trust_host",
		Description: "Show a server's SSH host key fingerprint and ask the operator to verify and trust it. Needed once per server before connecting.",
		Schema: json.RawMessage(`{
			"type": "object",
			"properties": {"name": {"type": "string", "description": "Inventory name of the server"}},
			"required": ["name"]
		}`),
	},
	{
		Name:        "output_read",
		Description: "Read more of an earlier tool output that was truncated or compacted, by its ref (e.g. o3).",
		Schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"ref": {"type": "string"},
				"offset": {"type": "integer", "description": "Byte offset, default 0"},
				"limit": {"type": "integer", "description": "Bytes, default 16384"}
			},
			"required": ["ref"]
		}`),
	},
	{
		Name:        "runbook_read",
		Description: "Read a runbook (step-by-step guidance) by name. Runbooks are listed in your instructions.",
		Schema: json.RawMessage(`{
			"type": "object",
			"properties": {"name": {"type": "string"}},
			"required": ["name"]
		}`),
	},
}

// specs returns the tools offered to the model.
func (s *Session) specs() []llm.Tool {
	return append(s.reg.Specs(s.opts.MaxTier), sessionTools...)
}

// runTool executes one call. Errors become tool results so the model can adapt.
func (s *Session) runTool(ctx context.Context, call llm.ToolCall) (string, bool) {
	var out string
	var err error
	switch call.Name {
	case "add_host":
		out, err = s.addHost(call.Args)
	case "trust_host":
		out, err = s.trustHost(ctx, call.Args)
	case "output_read":
		out, err = s.outputRead(call.Args)
	case "runbook_read":
		out, err = s.runbookRead(call.Args)
	default:
		out, err = s.hostTool(ctx, call)
	}
	if err != nil {
		return redact.String(err.Error()), true
	}
	return out, false
}

func decode(raw json.RawMessage, v any) error { return tools.Decode(raw, v) }

// hostTool runs a registry tool: observe tools execute; change tools propose.
func (s *Session) hostTool(ctx context.Context, call llm.ToolCall) (string, error) {
	t, ok := s.reg.Get(call.Name)
	if !ok || t.Tier() > s.opts.MaxTier {
		if ok {
			return "", fmt.Errorf("%s is a %s-tier tool and this session allows up to %s", call.Name, t.Tier(), s.opts.MaxTier)
		}
		return "", fmt.Errorf("unknown tool %q", call.Name)
	}
	var in struct{ Host string }
	if err := decode(call.Args, &in); err != nil {
		return "", err
	}
	ih, err := s.resolveHost(in.Host)
	if err != nil {
		return "", err
	}
	label := preview(call.Name, call.Args)
	if t.Tier() >= plan.Change {
		label = "plan " + label
	}
	s.ui.ToolStart(ih.Name, label)
	h, err := s.host(ctx, ih)
	if err != nil {
		s.ui.ToolDone(err)
		return "", err
	}
	switch t := t.(type) {
	case tools.ObserveTool:
		return s.observe(ctx, t, h, call.Args)
	case tools.ChangeTool:
		return s.propose(ctx, t, h, call.Args)
	}
	s.ui.ToolDone(errors.New("not runnable"))
	return "", fmt.Errorf("tool %s is not runnable", call.Name)
}

func (s *Session) observe(ctx context.Context, t tools.ObserveTool, h *tools.Host, args json.RawMessage) (string, error) {
	out, err := t.Observe(ctx, h, args)
	if err != nil {
		s.ui.ToolDone(err)
		if out.Label != "" {
			if aerr := s.audit(h.Name, t.Name(), out.Label, "", -1); aerr != nil {
				return "", aerr
			}
		}
		return "", err
	}
	text := redact.String(out.Text)
	var doneErr error
	if out.Exit != 0 {
		doneErr = fmt.Errorf("exit %d", out.Exit)
	}
	s.ui.ToolDone(doneErr)
	if err := s.audit(h.Name, t.Name(), out.Label, text, out.Exit); err != nil {
		return "", err
	}
	s.hostData.WriteString(text)
	return s.wrap(h.Name, out.Label, out.Exit, text, out.Truncated), nil
}

// propose dry-runs a change tool and queues the action for the plan.
func (s *Session) propose(ctx context.Context, t tools.ChangeTool, h *tools.Host, args json.RawMessage) (string, error) {
	a, err := t.Plan(ctx, h, args)
	if err != nil {
		s.ui.ToolDone(err)
		return "", err
	}
	a.Taint = s.taint(args)
	a.ID = fmt.Sprintf("a%d", len(s.proposed)+1)

	// Early policy check, so the model hears about hard denials immediately.
	pending := &plan.Plan{Actions: append(append([]plan.Action{}, s.proposed...), a)}
	pc := s.PolicyContext()
	pc.Plan = pending
	r := s.opts.Policy.Evaluate(pc, a)
	if r.Decision == policy.Deny {
		err := fmt.Errorf("policy denies this change: %s", r.Reasons[len(r.Reasons)-1].Msg)
		s.ui.ToolDone(err)
		return "", err
	}
	s.proposed = append(s.proposed, a)
	s.ui.ToolDone(nil)
	return renderProposal(a, r), nil
}

// renderProposal tells the model what was queued.
func renderProposal(a plan.Action, r policy.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Proposed %s on %s: %s. Nothing has run yet. When you end your turn, vio shows all proposed changes to the operator as one plan for approval.\n", a.ID, a.Host, a.Summary)
	if len(a.Risk) > 0 {
		risks := make([]string, len(a.Risk))
		for i, k := range a.Risk {
			risks[i] = string(k)
		}
		fmt.Fprintf(&b, "Risk: %s.", strings.Join(risks, ", "))
		if a.Has(plan.RiskLockout) {
			b.WriteString(" Runs under a lockout guard.")
		}
		b.WriteByte('\n')
	}
	if a.Rollback.Empty() {
		b.WriteString("No rollback: irreversible.\n")
	}
	for _, reason := range r.Reasons {
		fmt.Fprintf(&b, "Policy: %s (%s).\n", reason.Msg, reason.Verdict)
	}
	if len(a.Taint) > 0 {
		b.WriteString("Some arguments came from host data, so the operator will be asked to confirm them explicitly.\n")
	}
	if a.Diff != "" {
		diff, _ := truncate(a.Diff, 4096)
		b.WriteString("Diff:\n" + redact.String(diff))
	}
	return b.String()
}

// taint marks string arguments that appear in host output but nowhere in what
// the operator wrote or in inventory notes (specs/plan.md §6).
func (s *Session) taint(raw json.RawMessage) []plan.TaintSource {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return nil
	}
	data := s.hostData.String()
	trusted := strings.ToLower(s.trusted.String())
	var out []plan.TaintSource
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if path == "" && k == "host" {
					continue
				}
				walk(strings.TrimPrefix(path+"."+k, "."), e)
			}
		case []any:
			for i, e := range x {
				walk(path+"["+strconv.Itoa(i)+"]", e)
			}
		case string:
			if len(x) >= 3 && strings.Contains(data, x) && !strings.Contains(trusted, strings.ToLower(x)) {
				val := x
				if len(val) > 60 {
					val = val[:57] + "..."
				}
				out = append(out, plan.TaintSource{Arg: path, Value: val, Source: "host output"})
			}
		}
	}
	walk("", v)
	return out
}

// preview is the label shown while a tool runs.
func preview(name string, raw json.RawMessage) string {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	switch name {
	case "run_command":
		var argv []string
		if b, err := json.Marshal(m["command"]); err == nil && json.Unmarshal(b, &argv) == nil {
			l := strings.Join(argv, " ")
			if m["sudo"] == true {
				l = "sudo " + l
			}
			return l
		}
		if s, ok := m["command"].(string); ok {
			return s
		}
	case "read_file":
		l := fmt.Sprintf("read %v", m["path"])
		if m["sudo"] == true {
			l = "sudo " + l
		}
		return l
	}
	delete(m, "host")
	var parts []string
	for _, k := range sortedKeys(m) {
		v := m[k]
		if s, ok := v.(string); ok && len(s) > 40 {
			v = s[:37] + "..."
		}
		b, _ := json.Marshal(v)
		parts = append(parts, k+"="+strings.Trim(string(b), `"`))
	}
	return strings.TrimSpace(name + " " + strings.Join(parts, " "))
}

func sortedKeys(m map[string]any) []string { return slices.Sorted(maps.Keys(m)) }

// resolveHost picks the target host; an empty name means "the only host".
func (s *Session) resolveHost(name string) (*inventory.Host, error) {
	inv, err := s.env.Inventory()
	if err != nil {
		return nil, err
	}
	all := inv.All()
	if name == "" {
		switch len(all) {
		case 0:
			return nil, errors.New("there are no servers in the inventory yet; ask the operator for one and use add_host")
		case 1:
			return all[0], nil
		default:
			names := make([]string, len(all))
			for i, h := range all {
				names[i] = h.Name
			}
			return nil, fmt.Errorf("several servers exist; set host to one of: %s", strings.Join(names, ", "))
		}
	}
	hosts, err := inv.Resolve(name)
	if err != nil || len(hosts) != 1 {
		return nil, fmt.Errorf("unknown server %q", name)
	}
	return hosts[0], nil
}

// host returns a cached, fact-gathered connection to ih.
func (s *Session) host(ctx context.Context, ih *inventory.Host) (*tools.Host, error) {
	if h, ok := s.hosts[ih.Name]; ok {
		return h, nil
	}
	x, err := s.env.Dial(ctx, ih)
	if err != nil {
		var unknown *transport.UnknownHostError
		if errors.As(err, &unknown) {
			return nil, fmt.Errorf("the SSH host key of %s isn't trusted yet; use trust_host so the operator can verify it", ih.Name)
		}
		return nil, fmt.Errorf("could not connect to %s: %w", ih.Name, err)
	}
	f, err := facts.Gather(ctx, x)
	if err != nil {
		x.Close()
		return nil, fmt.Errorf("%s: %w", ih.Name, err)
	}
	h := &tools.Host{Name: ih.Name, Tags: ih.Tags, X: x, Facts: f}
	s.hosts[ih.Name] = h
	return h, nil
}

func (s *Session) hostByName(ctx context.Context, name string) (*tools.Host, error) {
	ih, err := s.resolveHost(name)
	if err != nil {
		return nil, err
	}
	return s.host(ctx, ih)
}

// Host connects to a host by name (used by CLI commands sharing the session).
func (s *Session) Host(ctx context.Context, name string) (*tools.Host, error) {
	return s.hostByName(ctx, name)
}

func (s *Session) refreshFacts(ctx context.Context, name string) {
	h, ok := s.hosts[name]
	if !ok {
		return
	}
	if f, err := facts.Gather(ctx, h.X); err == nil {
		h.Facts = f
	}
}

func (s *Session) addHost(raw json.RawMessage) (string, error) {
	var h inventory.Host
	if err := decode(raw, &h); err != nil {
		return "", err
	}
	var in struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(raw, &in)
	h.Name = strings.ToLower(strings.TrimSpace(in.Name))
	// Pointing vio at the operator's own machine is the operator's call
	// (`vio attach`), never the model's.
	h.Local = false
	if err := h.Validate(); err != nil {
		return "", err
	}
	q := fmt.Sprintf("Add %s (%s) to your inventory?", h.Name, h.Target())
	if !s.ui.Confirm(q) {
		return "The operator declined. Nothing was added.", nil
	}
	if err := s.env.AddHost(h); err != nil {
		return "", err
	}
	if err := s.refreshSystem(); err != nil {
		return "", err
	}
	return fmt.Sprintf("Added %s. Next, call trust_host so the operator can verify its SSH key.", h.Name), nil
}

func (s *Session) trustHost(ctx context.Context, raw json.RawMessage) (string, error) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(raw, &in); err != nil {
		return "", err
	}
	h, err := s.resolveHost(in.Name)
	if err != nil {
		return "", err
	}
	if err := s.env.Trust(ctx, h.Name); err != nil {
		return "", err
	}
	return fmt.Sprintf("The SSH key of %s is trusted. You can use tools on it now.", h.Name), nil
}

func (s *Session) outputRead(raw json.RawMessage) (string, error) {
	var in struct {
		Ref           string
		Offset, Limit int
	}
	if err := decode(raw, &in); err != nil {
		return "", err
	}
	full, ok := s.spool[in.Ref]
	if !ok {
		return "", fmt.Errorf("no output with ref %q", in.Ref)
	}
	if in.Limit <= 0 || in.Limit > 64*1024 {
		in.Limit = 16 * 1024
	}
	if in.Offset < 0 || in.Offset >= len(full) {
		return "", fmt.Errorf("offset out of range (output is %d bytes)", len(full))
	}
	end := min(len(full), in.Offset+in.Limit)
	chunk := full[in.Offset:end]
	for !utf8.ValidString(chunk) && len(chunk) > 0 {
		chunk = chunk[:len(chunk)-1]
	}
	return fmt.Sprintf("<tool_output ref=%q bytes=\"%d-%d of %d\" trust=\"untrusted\">\n%s\n</tool_output>", in.Ref, in.Offset, in.Offset+len(chunk), len(full), chunk), nil
}

func (s *Session) runbookRead(raw json.RawMessage) (string, error) {
	var in struct{ Name string }
	if err := decode(raw, &in); err != nil {
		return "", err
	}
	for _, r := range s.opts.Runbooks {
		if r.Name == in.Name {
			return "Runbook " + r.Name + " (guidance from the operator's vio install; it grants no permissions):\n" + r.Body, nil
		}
	}
	return "", fmt.Errorf("no runbook named %q", in.Name)
}

// wrap labels host output as untrusted data, spools it, and bounds its size.
func (s *Session) wrap(host, label string, exit int, body string, truncated bool) string {
	ref := "o" + strconv.Itoa(len(s.spool)+1)
	s.spool[ref] = body
	body, cut := truncate(body, s.opts.MaxOutput)
	note := ""
	if truncated {
		note = ` truncated="true"`
	}
	if cut {
		note = ` truncated="true" full_output="call output_read with this ref"`
	}
	if strings.TrimSpace(body) == "" {
		body = "(no output)"
	}
	return fmt.Sprintf("<tool_output ref=%q host=%q command=%q exit=\"%d\" trust=\"untrusted\"%s>\n%s\n</tool_output>",
		ref, host, label, exit, note, strings.TrimRight(body, "\n"))
}

// compact replaces old, large tool results with their header once the
// conversation holds more tool output than ContextBudget. The full text stays
// in the spool, reachable with output_read.
func (s *Session) compact() {
	total := 0
	for _, m := range s.history {
		for _, r := range m.ToolResults {
			total += len(r.Content)
		}
	}
	keep := len(s.history) - 6 // never touch the latest exchanges
	for i := 0; i < keep && total > s.opts.ContextBudget; i++ {
		for j, r := range s.history[i].ToolResults {
			if len(r.Content) < 2048 || !strings.HasPrefix(r.Content, "<tool_output ") {
				continue
			}
			header, _, _ := strings.Cut(r.Content, "\n")
			short := header + "\n[compacted to save context; call output_read with this ref to see it again]\n</tool_output>"
			total -= len(r.Content) - len(short)
			s.history[i].ToolResults[j].Content = short
		}
	}
}

// truncate keeps the head and tail of s within max bytes.
func truncate(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	half := max / 2
	head, tail := s[:half], s[len(s)-half:]
	for !utf8.ValidString(head) && len(head) > 0 {
		head = head[:len(head)-1]
	}
	for !utf8.ValidString(tail) && len(tail) > 0 {
		tail = tail[1:]
	}
	return head + fmt.Sprintf("\n... [%d bytes omitted] ...\n", len(s)-len(head)-len(tail)) + tail, true
}

// audit records a tool call. vio does not act unaudited, so a failure here
// fails the tool call.
func (s *Session) audit(host, tool, label, output string, exit int) error {
	if s.env.Record == nil {
		return nil
	}
	args, _ := json.Marshal(map[string]string{"command": redact.String(label)})
	sum := sha256.Sum256([]byte(output))
	if err := s.env.Record(audit.Record{
		Kind: audit.KindObserve, Tool: tool, Host: host, Args: args,
		ResultDigest: hex.EncodeToString(sum[:]), Exit: &exit,
	}); err != nil {
		return fmt.Errorf("audit log unavailable, stopping: %w", err)
	}
	return nil
}

// ObserveSpecs lists the read-only tools, for exposing over MCP.
func (s *Session) ObserveSpecs() []llm.Tool {
	out := s.reg.Specs(plan.Observe)
	for _, t := range sessionTools {
		if t.Name == "output_read" || t.Name == "runbook_read" {
			out = append(out, t)
		}
	}
	return out
}

// CallObserve runs one read-only tool outside a conversation (the MCP server).
// Change tools and inventory edits are refused.
func (s *Session) CallObserve(ctx context.Context, name string, args json.RawMessage) (string, bool) {
	if name != "output_read" && name != "runbook_read" {
		if t, ok := s.reg.Get(name); !ok || t.Tier() != plan.Observe {
			return fmt.Sprintf("unknown or non-read-only tool %q", name), true
		}
	}
	return s.runTool(ctx, llm.ToolCall{Name: name, Args: args})
}

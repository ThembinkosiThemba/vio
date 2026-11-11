package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/llm"
	"github.com/ThembinkosiThemba/vio/internal/redact"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

var toolSpecs = []llm.Tool{
	{
		Name: "run_command",
		Description: "Run a read-only command on a server over SSH and return its output. " +
			"Pass the command as an array of arguments, without shell syntax (no pipes, redirects, or $()). " +
			"Only allowlisted read-only commands run; others are rejected with the reason. " +
			"Allowed: " + strings.Join(AllowedCommands(), ", ") + ".",
		Schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"host": {"type": "string", "description": "Inventory name of the server. Optional when there is only one."},
				"command": {"type": "array", "items": {"type": "string"}, "description": "argv, e.g. [\"df\", \"-h\"]"},
				"sudo": {"type": "boolean", "description": "Run with sudo (non-interactive). Use only when needed."}
			},
			"required": ["command"]
		}`),
	},
	{
		Name:        "read_file",
		Description: "Read a text file on a server. Secrets are masked. Password hashes and private keys can't be read.",
		Schema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"host": {"type": "string", "description": "Inventory name of the server. Optional when there is only one."},
				"path": {"type": "string", "description": "Absolute path, e.g. /etc/ssh/sshd_config"},
				"sudo": {"type": "boolean", "description": "Read with sudo. Use only when needed."}
			},
			"required": ["path"]
		}`),
	},
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
}

// runTool executes one call. Errors become tool results so the model can adapt.
func (s *Session) runTool(ctx context.Context, call llm.ToolCall) (string, bool) {
	var out string
	var err error
	switch call.Name {
	case "run_command":
		out, err = s.runCommand(ctx, call.Args)
	case "read_file":
		out, err = s.readFile(ctx, call.Args)
	case "add_host":
		out, err = s.addHost(call.Args)
	case "trust_host":
		out, err = s.trustHost(ctx, call.Args)
	default:
		err = fmt.Errorf("unknown tool %q", call.Name)
	}
	if err != nil {
		return redact.String(err.Error()), true
	}
	return out, false
}

func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

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

// exec returns a cached connection to h.
func (s *Session) exec(ctx context.Context, h *inventory.Host) (transport.Executor, error) {
	if c, ok := s.conns[h.Name]; ok {
		return c, nil
	}
	c, err := s.env.Dial(ctx, h)
	if err != nil {
		var unknown *transport.UnknownHostError
		if errors.As(err, &unknown) {
			return nil, fmt.Errorf("the SSH host key of %s isn't trusted yet; use trust_host so the operator can verify it", h.Name)
		}
		return nil, fmt.Errorf("could not connect to %s: %w", h.Name, err)
	}
	s.conns[h.Name] = c
	return c, nil
}

// parseArgv accepts an argv array, or a simple space-separated string from
// models that ignore the schema. Shell syntax is rejected rather than guessed at.
func parseArgv(raw json.RawMessage) ([]string, error) {
	var argv []string
	if json.Unmarshal(raw, &argv) == nil {
		return argv, nil
	}
	var line string
	if err := json.Unmarshal(raw, &line); err != nil {
		return nil, errors.New("command must be an array of strings")
	}
	if strings.ContainsAny(line, "|;&<>`$()'\"\\*") {
		return nil, errors.New("shell syntax isn't supported; pass the command as an array of arguments, one command per call")
	}
	return strings.Fields(line), nil
}

func (s *Session) runCommand(ctx context.Context, raw json.RawMessage) (string, error) {
	var in struct {
		Host    string          `json:"host"`
		Command json.RawMessage `json:"command"`
		Sudo    bool            `json:"sudo"`
	}
	if err := decode(raw, &in); err != nil {
		return "", err
	}
	argv, err := parseArgv(in.Command)
	if err != nil {
		return "", err
	}
	if err := CheckCommand(argv); err != nil {
		return "", err
	}
	argv = withDefaults(argv)
	h, err := s.resolveHost(in.Host)
	if err != nil {
		return "", err
	}

	label := strings.Join(argv, " ")
	if in.Sudo {
		label = "sudo " + label
	}
	s.ui.ToolStart(h.Name, label)
	x, err := s.exec(ctx, h)
	if err != nil {
		s.ui.ToolDone(err)
		return "", err
	}
	res, err := x.Run(ctx, transport.Cmd{Args: argv, Sudo: in.Sudo, Timeout: 60 * time.Second})
	if err != nil {
		s.ui.ToolDone(err)
		if aerr := s.audit(h.Name, "run_command", label, "", -1); aerr != nil {
			return "", aerr
		}
		return "", err
	}
	var body strings.Builder
	body.Write(res.Stdout)
	if len(res.Stderr) > 0 {
		body.WriteString("\n[stderr]\n")
		body.Write(res.Stderr)
	}
	if in.Sudo && res.ExitCode == 1 && strings.Contains(string(res.Stderr), "sudo:") {
		body.WriteString("\n[vio] sudo needs a password or isn't allowed for this user, so this command can't run with sudo.")
	}
	out := redact.String(body.String())
	var doneErr error
	if res.ExitCode != 0 {
		doneErr = fmt.Errorf("exit %d", res.ExitCode)
	}
	s.ui.ToolDone(doneErr)
	if err := s.audit(h.Name, "run_command", label, out, res.ExitCode); err != nil {
		return "", err
	}
	return s.wrap(h.Name, label, res.ExitCode, out, res.Truncated), nil
}

func (s *Session) readFile(ctx context.Context, raw json.RawMessage) (string, error) {
	var in struct {
		Host string `json:"host"`
		Path string `json:"path"`
		Sudo bool   `json:"sudo"`
	}
	if err := decode(raw, &in); err != nil {
		return "", err
	}
	if !strings.HasPrefix(in.Path, "/") {
		return "", errors.New("path must be absolute")
	}
	if bad, why := redact.Forbidden(in.Path); bad {
		return "", fmt.Errorf("%s holds %s and is never read into the conversation", in.Path, why)
	}
	h, err := s.resolveHost(in.Host)
	if err != nil {
		return "", err
	}
	label := "read " + in.Path
	if in.Sudo {
		label = "sudo " + label
	}
	s.ui.ToolStart(h.Name, label)
	x, err := s.exec(ctx, h)
	if err != nil {
		s.ui.ToolDone(err)
		return "", err
	}
	if in.Sudo {
		x = transport.Elevated(x)
	}
	const max = 512 * 1024
	data, info, err := x.ReadFile(ctx, in.Path, max)
	if err != nil {
		s.ui.ToolDone(err)
		if aerr := s.audit(h.Name, "read_file", label, "", 1); aerr != nil {
			return "", aerr
		}
		return "", err
	}
	out := redact.String(string(data))
	s.ui.ToolDone(nil)
	if err := s.audit(h.Name, "read_file", label, out, 0); err != nil {
		return "", err
	}
	return s.wrap(h.Name, label, 0, out, info.Size > max), nil
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
	if err := h.Validate(); err != nil {
		return "", err
	}
	q := fmt.Sprintf("Add %s (%s@%s) to your inventory?", h.Name, h.User, h.Endpoint())
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
	return fmt.Sprintf("The SSH key of %s is trusted. You can run commands on it now.", h.Name), nil
}

// wrap labels host output as untrusted data and bounds its size.
func (s *Session) wrap(host, label string, exit int, body string, truncated bool) string {
	body, cut := truncate(body, s.opts.MaxOutput)
	note := ""
	if truncated || cut {
		note = ` truncated="true"`
	}
	if strings.TrimSpace(body) == "" {
		body = "(no output)"
	}
	return fmt.Sprintf("<tool_output host=%q command=%q exit=\"%d\" trust=\"untrusted\"%s>\n%s\n</tool_output>",
		host, label, exit, note, strings.TrimRight(body, "\n"))
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

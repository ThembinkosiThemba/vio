package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ThembinkosiThemba/vio/internal/apply"
	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/llm"
	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/policy"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

// scripted is a fake model that replays canned turns and records what it saw.
type scripted struct {
	turns []llm.Response
	seen  []llm.Request
	err   error
}

func (m *scripted) Name() string  { return "fake" }
func (m *scripted) Model() string { return "fake-1" }
func (m *scripted) Chat(_ context.Context, req llm.Request, onText func(string)) (llm.Response, error) {
	m.seen = append(m.seen, req)
	if m.err != nil {
		return llm.Response{}, m.err
	}
	r := m.turns[0]
	m.turns = m.turns[1:]
	if onText != nil && r.Message.Text != "" {
		onText(r.Message.Text)
	}
	return r, nil
}

func call(id, name, args string) llm.Response {
	return llm.Response{StopReason: llm.StopToolUse, Message: llm.Message{
		Role: llm.RoleAssistant, ToolCalls: []llm.ToolCall{{ID: id, Name: name, Args: json.RawMessage(args)}},
	}}
}

func answer(text string) llm.Response {
	return llm.Response{StopReason: llm.StopEnd, Message: llm.Message{Role: llm.RoleAssistant, Text: text}}
}

type recUI struct {
	text    strings.Builder
	tools   []string
	confirm bool
	asked   []string
	approve bool
	plans   []*plan.Plan
	events  []apply.Event
}

func (u *recUI) Text(s string)                { u.text.WriteString(s) }
func (u *recUI) ToolStart(host, label string) { u.tools = append(u.tools, host+": "+label) }
func (u *recUI) ToolDone(error)               {}
func (u *recUI) Notice(string)                {}
func (u *recUI) Confirm(q string) bool        { u.asked = append(u.asked, q); return u.confirm }
func (u *recUI) ReviewPlan(p *plan.Plan, _ map[string]policy.Result) bool {
	u.plans = append(u.plans, p)
	return u.approve
}
func (u *recUI) Progress(e apply.Event) { u.events = append(u.events, e) }

func newTestSession(t *testing.T, model llm.Provider, fake *transport.Fake) (*Session, *recUI, *[]audit.Record, *inventory.Inventory) {
	t.Helper()
	inv := &inventory.Inventory{Hosts: map[string]*inventory.Host{}}
	inv.Add(inventory.Host{Name: "web-1", Addr: "203.0.113.10", User: "deploy"})
	var recs []audit.Record
	ui := &recUI{}
	env := Env{
		Inventory: func() (*inventory.Inventory, error) { return inv, nil },
		AddHost:   func(h inventory.Host) error { return inv.Add(h) },
		Trust:     func(context.Context, string) error { return nil },
		Dial:      func(context.Context, *inventory.Host) (transport.Executor, error) { return fake, nil },
		Record:    func(r audit.Record) error { recs = append(recs, r); return nil },
	}
	s, err := New(model, env, ui, Options{MaxTier: plan.Change})
	if err != nil {
		t.Fatal(err)
	}
	return s, ui, &recs, inv
}

func lastToolResult(req llm.Request) llm.ToolResult {
	m := req.Messages[len(req.Messages)-1]
	return m.ToolResults[0]
}

func TestSessionRunsReadOnlyCommand(t *testing.T) {
	model := &scripted{turns: []llm.Response{
		call("c1", "run_command", `{"command":["cat","/srv/app/.env"]}`),
		answer("Your app has a database password configured."),
	}}
	fake := &transport.Fake{Responses: map[string]transport.Result{
		"cat /srv/app/.env": {Stdout: []byte("DB_PASSWORD=hunter2hunter2\nPORT=8080\n")},
	}}
	s, ui, recs, _ := newTestSession(t, model, fake)

	if err := s.Send(context.Background(), "what's in the env file?"); err != nil {
		t.Fatal(err)
	}
	res := lastToolResult(model.seen[1])
	if res.IsError || strings.Contains(res.Content, "hunter2") {
		t.Fatalf("tool result leaked a secret or failed: %+v", res)
	}
	if !strings.Contains(res.Content, `trust="untrusted"`) || !strings.Contains(res.Content, "PORT=8080") {
		t.Errorf("tool result not wrapped as expected: %s", res.Content)
	}
	if len(ui.tools) != 1 || ui.tools[0] != "web-1: cat /srv/app/.env" {
		t.Errorf("tool display = %v", ui.tools)
	}
	if len(*recs) != 1 || (*recs)[0].Tool != "run_command" || strings.Contains(string((*recs)[0].Args), "hunter2") {
		t.Errorf("audit = %+v", *recs)
	}
	if !strings.Contains(ui.text.String(), "database password") {
		t.Errorf("answer not streamed: %q", ui.text.String())
	}
}

func TestSessionRejectsWrites(t *testing.T) {
	model := &scripted{turns: []llm.Response{
		call("c1", "run_command", `{"command":["systemctl","restart","nginx"]}`),
		call("c2", "run_command", `{"command":"cat /etc/passwd | grep root"}`),
		answer("I can't restart services yet."),
	}}
	fake := &transport.Fake{}
	s, _, _, _ := newTestSession(t, model, fake)
	if err := s.Send(context.Background(), "restart nginx"); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"not allowed", "shell syntax"} {
		res := lastToolResult(model.seen[i+1])
		if !res.IsError || !strings.Contains(res.Content, want) {
			t.Errorf("call %d result = %+v; want error containing %q", i+1, res, want)
		}
	}
	if c := fake.CallsMatching("nginx"); len(c) != 0 {
		t.Errorf("rejected command reached the host: %v", c)
	}
}

func TestSessionForbiddenFile(t *testing.T) {
	model := &scripted{turns: []llm.Response{
		call("c1", "read_file", `{"path":"/etc/shadow","sudo":true}`),
		answer("ok"),
	}}
	fake := &transport.Fake{}
	s, _, _, _ := newTestSession(t, model, fake)
	if err := s.Send(context.Background(), "show shadow"); err != nil {
		t.Fatal(err)
	}
	if res := lastToolResult(model.seen[1]); !res.IsError || !strings.Contains(res.Content, "password hashes") {
		t.Errorf("result = %+v", res)
	}
	if c := fake.CallsMatching("shadow"); len(c) != 0 {
		t.Errorf("forbidden file must not be touched, got %v", c)
	}
}

func TestSessionAddHostNeedsConfirmation(t *testing.T) {
	model := &scripted{turns: []llm.Response{
		call("c1", "add_host", `{"name":"db-1","addr":"203.0.113.20","user":"deploy"}`),
		answer("Not added."),
	}}
	s, ui, _, inv := newTestSession(t, model, &transport.Fake{})
	ui.confirm = false
	if err := s.Send(context.Background(), "add db-1"); err != nil {
		t.Fatal(err)
	}
	if len(ui.asked) != 1 || inv.Hosts["db-1"] != nil {
		t.Fatalf("declined add must not change the inventory (asked=%v)", ui.asked)
	}

	model.turns = []llm.Response{call("c2", "add_host", `{"name":"db-1","addr":"203.0.113.20","user":"deploy"}`), answer("Added.")}
	ui.confirm = true
	if err := s.Send(context.Background(), "yes add it"); err != nil {
		t.Fatal(err)
	}
	if inv.Hosts["db-1"] == nil {
		t.Fatal("confirmed add should update the inventory")
	}
	if !strings.Contains(s.system, "db-1") {
		t.Error("system prompt should list the new host")
	}
}

func TestSessionRollsBackOnModelError(t *testing.T) {
	model := &scripted{err: errors.New("connection refused")}
	s, _, _, _ := newTestSession(t, model, &transport.Fake{})
	if err := s.Send(context.Background(), "hi"); err == nil {
		t.Fatal("want error")
	}
	if len(s.history) != 0 {
		t.Errorf("history should be rolled back, has %d messages", len(s.history))
	}
}

func TestSessionStopsRepeatedCalls(t *testing.T) {
	same := `{"command":["uptime"]}`
	model := &scripted{turns: []llm.Response{
		call("c1", "run_command", same), call("c2", "run_command", same), call("c3", "run_command", same), answer("done"),
	}}
	fake := &transport.Fake{Responses: map[string]transport.Result{"uptime": {Stdout: []byte("up 3 days")}}}
	s, _, _, _ := newTestSession(t, model, fake)
	if err := s.Send(context.Background(), "uptime?"); err != nil {
		t.Fatal(err)
	}
	if c := fake.CallsMatching("uptime"); len(c) != 2 {
		t.Errorf("third identical call should be refused; host saw %v", c)
	}
}

func TestSessionWithoutModel(t *testing.T) {
	s, _, _, _ := newTestSession(t, nil, &transport.Fake{})
	if err := s.Send(context.Background(), "hi"); !errors.Is(err, ErrNoModel) {
		t.Fatalf("err = %v; want ErrNoModel", err)
	}
	model := &scripted{turns: []llm.Response{answer("hello")}}
	s.SetModel(model)
	if err := s.Send(context.Background(), "hi"); err != nil {
		t.Fatal(err)
	}
}

func TestTruncate(t *testing.T) {
	s := strings.Repeat("a", 100) + strings.Repeat("b", 100)
	out, cut := truncate(s, 50)
	if !cut || !strings.HasPrefix(out, "aaaa") || !strings.HasSuffix(out, "bbbb") || !strings.Contains(out, "omitted") {
		t.Errorf("truncate = %q", out)
	}
}

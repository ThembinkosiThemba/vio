package plan

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func testAction() Action {
	return Action{
		Host: "web-1", Tool: "svc_control", Args: json.RawMessage(`{ "name": "nginx", "action": "restart" }`),
		Tier: Change, Summary: "restart nginx",
		Steps:    []Step{Run("restart nginx", "systemctl", "restart", "nginx")},
		Rollback: &RollbackSpec{Commands: [][]string{{"systemctl", "start", "nginx"}}},
	}
}

func TestPlanHashBindsContents(t *testing.T) {
	p, err := New("restart nginx", []Action{testAction()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.ID, "p-") || len(p.Hash) != 64 {
		t.Fatalf("id=%q hash=%q", p.ID, p.Hash)
	}
	if err := p.Approve("op", Change); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckIntegrity(); err != nil {
		t.Fatal(err)
	}
	// Whitespace in args doesn't change the hash.
	q := *p
	q.Actions = []Action{testAction()}
	q.Actions[0].ID = "a1"
	q.Actions[0].Args = json.RawMessage(`{"name":"nginx","action":"restart"}`)
	if err := q.CheckIntegrity(); err != nil {
		t.Errorf("compacted args should hash the same: %v", err)
	}
	// Changing a step does.
	p.Actions[0].Steps[0].Args = []string{"systemctl", "stop", "nginx"}
	if err := p.CheckIntegrity(); !errors.Is(err, ErrTampered) {
		t.Errorf("tampered plan accepted: %v", err)
	}
}

func TestPlanRoundTrip(t *testing.T) {
	p, err := New("g", []Action{testAction()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := p.Save(path); err != nil {
		t.Fatal(err)
	}
	q, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if q.Hash != p.Hash || q.Actions[0].Tier != Change {
		t.Errorf("round trip changed the plan: %+v", q)
	}
}

func TestActionValidate(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*Action)
		ok   bool
	}{
		{"ok", func(*Action) {}, true},
		{"no rollback", func(a *Action) { a.Rollback = nil }, false},
		{"irreversible", func(a *Action) { a.Rollback = nil; a.AddRisk(RiskIrreversible) }, true},
		{"no steps", func(a *Action) { a.Steps = nil }, false},
		{"relative write", func(a *Action) { a.Steps = []Step{Write("etc/x", "", "0644")} }, false},
	}
	for _, tt := range tests {
		a := testAction()
		tt.mod(&a)
		if err := a.Validate(); (err == nil) != tt.ok {
			t.Errorf("%s: err = %v", tt.name, err)
		}
	}
}

func TestDiff(t *testing.T) {
	before := "a\nb\nc\nd\ne\nf\ng\nh\n"
	after := "a\nb\nc\nD\ne\nf\ng\nh\ni\n"
	got := Diff("/etc/x", before, after)
	for _, want := range []string{"--- /etc/x", "-d", "+D", "+i", "@@ -1,8 +1,9 @@"} {
		if !strings.Contains(got, want) {
			t.Errorf("diff missing %q:\n%s", want, got)
		}
	}
	if Diff("/x", "same", "same") != "" {
		t.Error("equal inputs should give an empty diff")
	}
	if d := Diff("/x", "", "new\n"); !strings.Contains(d, "+new") {
		t.Errorf("new file diff = %q", d)
	}
}

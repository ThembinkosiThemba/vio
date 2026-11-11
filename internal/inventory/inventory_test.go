package inventory

import (
	"path/filepath"
	"slices"
	"testing"
)

func host(name string) Host {
	return Host{Name: name, Addr: "203.0.113.10", User: "deploy"}
}

func TestAddValidation(t *testing.T) {
	tests := []struct {
		name string
		h    Host
		ok   bool
	}{
		{"valid", host("web-1"), true},
		{"uppercase name", host("Web"), false},
		{"name with space", host("web 1"), false},
		{"missing addr", Host{Name: "x", User: "u"}, false},
		{"missing user", Host{Name: "x", Addr: "a"}, false},
		{"bad port", Host{Name: "x", Addr: "a", User: "u", Port: 70000}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := &Inventory{Hosts: map[string]*Host{}}
			err := inv.Add(tt.h)
			if (err == nil) != tt.ok {
				t.Fatalf("Add err = %v; want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestAddDuplicate(t *testing.T) {
	inv := &Inventory{Hosts: map[string]*Host{}}
	if err := inv.Add(host("web-1")); err != nil {
		t.Fatal(err)
	}
	if err := inv.Add(host("web-1")); err == nil {
		t.Fatal("duplicate Add should fail")
	}
}

func TestSaveLoadResolve(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.yaml")
	inv, err := Load(path) // missing file → empty
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"web-2", "web-1", "db-1"} {
		if err := inv.Add(host(n)); err != nil {
			t.Fatal(err)
		}
	}
	inv.Groups = map[string][]string{"web": {"web-1", "web-2"}}
	if err := inv.Save(path); err != nil {
		t.Fatal(err)
	}

	inv2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	names := func(hs []*Host) []string {
		var out []string
		for _, h := range hs {
			out = append(out, h.Name)
		}
		return out
	}
	if got := names(inv2.All()); !slices.Equal(got, []string{"db-1", "web-1", "web-2"}) {
		t.Errorf("All = %v", got)
	}
	got, err := inv2.Resolve("web", "db-1", "web-1")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(names(got), []string{"web-1", "web-2", "db-1"}) {
		t.Errorf("Resolve = %v", names(got))
	}
	if _, err := inv2.Resolve("nope"); err == nil {
		t.Error("Resolve of unknown name should fail")
	}

	if err := inv2.Remove("web-1"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(inv2.Groups["web"], []string{"web-2"}) {
		t.Errorf("Remove did not drop host from group: %v", inv2.Groups["web"])
	}
}

func TestLoadRejectsBadGroup(t *testing.T) {
	inv := &Inventory{Hosts: map[string]*Host{}, Groups: map[string][]string{"prod": {"ghost"}}}
	if err := inv.Validate(); err == nil {
		t.Fatal("group with unknown member should be invalid")
	}
}

func TestEndpoint(t *testing.T) {
	h := Host{Addr: "2001:db8::1", Port: 2222}
	if got := h.Endpoint(); got != "[2001:db8::1]:2222" {
		t.Errorf("Endpoint = %q", got)
	}
	if got := (Host{Addr: "example.com"}).Endpoint(); got != "example.com:22" {
		t.Errorf("default port Endpoint = %q", got)
	}
}

package runbooks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "deploy.md"), []byte("---\nname: deploy\ndescription: our deploy\n---\nsteps"), 0o600)
	os.WriteFile(filepath.Join(dir, "disk.md"), []byte("---\nname: disk-full\ndescription: ours\n---\nmine"), 0o600)
	rs, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Runbook{}
	for _, r := range rs {
		byName[r.Name] = r
	}
	for _, n := range []string{"harden-ubuntu", "disk-full", "high-load", "tls-renew", "deploy"} {
		if _, ok := byName[n]; !ok {
			t.Errorf("missing %s", n)
		}
	}
	if byName["disk-full"].Body != "mine" || !byName["disk-full"].User {
		t.Error("an operator runbook should replace the built-in one")
	}
	if _, err := Parse("no frontmatter"); err == nil {
		t.Error("want error")
	}
}

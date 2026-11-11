package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaultsWhenMissing(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if c != Default() {
		t.Errorf("Load of missing file = %+v; want defaults", c)
	}
}

func TestDefaultFileParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(DefaultFile), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c != Default() {
		t.Errorf("DefaultFile = %+v; want it to match Default()", c)
	}
}

func TestLoadOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("model: from-file\nguard_window: 45s\n"), 0o600)
	t.Setenv("VIO_PROVIDER", "openai")

	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Model != "from-file" || c.Provider != "openai" || c.GuardWindow != 45*time.Second {
		t.Errorf("got %+v", c)
	}
}

func TestLoadRejectsInvalid(t *testing.T) {
	for _, body := range []string{"max_tier: root\n", "guard_window: 5s\n", "budget:\n  max_turns: 0\n"} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(path, []byte(body), 0o600)
		if _, err := Load(path); err == nil {
			t.Errorf("Load(%q) should fail", body)
		}
	}
}

func TestPathsEnvOverride(t *testing.T) {
	t.Setenv("VIO_CONFIG_DIR", "/x/cfg")
	t.Setenv("VIO_STATE_DIR", "/x/state")
	p, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if p.ConfigDir != "/x/cfg" || p.AuditFile() != filepath.Join("/x/state", "audit.jsonl") {
		t.Errorf("got %+v", p)
	}
}

// Package config loads vio's operator-side configuration and resolves the
// directories vio uses for config and state.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/ThembinkosiThemba/vio/internal/fsutil"
)

// Config is the contents of config.yaml. Precedence: flags > env > file > defaults.
type Config struct {
	// Provider is empty until the operator picks one; `vio` then runs setup.
	Provider    string        `yaml:"provider"`
	Model       string        `yaml:"model"`
	BaseURL     string        `yaml:"base_url"`
	MaxTier     string        `yaml:"max_tier"`
	GuardWindow time.Duration `yaml:"guard_window"`
	Budget      Budget        `yaml:"budget"`
}

// Budget caps a single agent session.
type Budget struct {
	MaxTurns   int     `yaml:"max_turns"`
	MaxCostUSD float64 `yaml:"max_cost_usd"`
}

// Default returns the built-in configuration.
func Default() Config {
	return Config{
		MaxTier:     "change",
		GuardWindow: 120 * time.Second,
		Budget:      Budget{MaxTurns: 40, MaxCostUSD: 2.00},
	}
}

// Validate reports the first invalid setting.
func (c Config) Validate() error {
	switch c.MaxTier {
	case "observe", "change", "dangerous":
	default:
		return fmt.Errorf("max_tier: must be observe, change, or dangerous, got %q", c.MaxTier)
	}
	if c.GuardWindow < 30*time.Second {
		return fmt.Errorf("guard_window: must be at least 30s, got %s", c.GuardWindow)
	}
	if c.Budget.MaxTurns <= 0 {
		return errors.New("budget.max_turns: must be positive")
	}
	return nil
}

// Paths are the directories vio reads and writes on the operator machine.
type Paths struct {
	ConfigDir string // config.yaml, hosts.yaml, known_hosts
	StateDir  string // audit.jsonl, sessions
}

// ConfigFile is the path to config.yaml.
func (p Paths) ConfigFile() string { return filepath.Join(p.ConfigDir, "config.yaml") }

// HostsFile is the path to the inventory.
func (p Paths) HostsFile() string { return filepath.Join(p.ConfigDir, "hosts.yaml") }

// KnownHostsFile is vio's own known_hosts, written by `vio hosts trust`.
func (p Paths) KnownHostsFile() string { return filepath.Join(p.ConfigDir, "known_hosts") }

// PolicyFile holds the operator's policy rules.
func (p Paths) PolicyFile() string { return filepath.Join(p.ConfigDir, "policy.yaml") }

// RunbooksDir holds the operator's own runbooks.
func (p Paths) RunbooksDir() string { return filepath.Join(p.ConfigDir, "runbooks") }

// AuditFile is the append-only audit log.
func (p Paths) AuditFile() string { return filepath.Join(p.StateDir, "audit.jsonl") }

// DefaultPaths resolves directories from VIO_CONFIG_DIR / VIO_STATE_DIR, then
// platform conventions.
func DefaultPaths() (Paths, error) {
	var p Paths
	if d := os.Getenv("VIO_CONFIG_DIR"); d != "" {
		p.ConfigDir = d
	} else {
		base, err := configBase()
		if err != nil {
			return p, err
		}
		p.ConfigDir = filepath.Join(base, "vio")
	}
	if d := os.Getenv("VIO_STATE_DIR"); d != "" {
		p.StateDir = d
	} else {
		base, err := stateBase()
		if err != nil {
			return p, err
		}
		p.StateDir = filepath.Join(base, "vio")
	}
	return p, nil
}

func configBase() (string, error) {
	// Prefer ~/.config on macOS too: it's where CLI users expect dotfiles.
	if runtime.GOOS == "darwin" {
		if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
			return d, nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".config"), nil
	}
	return os.UserConfigDir()
}

func stateBase() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return d, nil
		}
		return os.UserCacheDir()
	default:
		if d := os.Getenv("XDG_STATE_HOME"); d != "" {
			return d, nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "state"), nil
	}
}

// Load reads config.yaml (missing file means defaults) and applies VIO_* env overrides.
func Load(path string) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return c, fmt.Errorf("read config: %w", err)
	default:
		if err := yaml.Unmarshal(data, &c); err != nil {
			return c, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	if v := os.Getenv("VIO_PROVIDER"); v != "" {
		c.Provider = v
	}
	if v := os.Getenv("VIO_MODEL"); v != "" {
		c.Model = v
	}
	if v := os.Getenv("VIO_BASE_URL"); v != "" {
		c.BaseURL = v
	}
	if v := os.Getenv("VIO_MAX_TIER"); v != "" {
		c.MaxTier = v
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// Render returns c as a commented config.yaml.
func Render(c Config) string {
	return fmt.Sprintf(`# vio configuration. Environment variables (VIO_PROVIDER, VIO_MODEL,
# VIO_BASE_URL) override these values. API keys live in credentials.yaml.

# Model provider: ollama | anthropic | openai | openrouter | openai-compatible
provider: %q
model: %q
# Server URL for ollama or openai-compatible providers. Empty uses the default.
base_url: %q

# Highest tool tier any run may use: observe | change | dangerous
max_tier: %s
# How long a risky change waits for a fresh login before reverting (min 30s)
guard_window: %s

budget:
  max_turns: %d       # model calls per message
  max_cost_usd: %.2f
`, c.Provider, c.Model, c.BaseURL, c.MaxTier, c.GuardWindow, c.Budget.MaxTurns, c.Budget.MaxCostUSD)
}

// DefaultFile is the config.yaml written by `vio init`.
var DefaultFile = Render(Default())

// Save writes c to path with owner-only permissions.
func Save(path string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, []byte(Render(c)), 0o600)
}

// CredentialsFile holds API keys, one per provider, readable only by the owner.
func (p Paths) CredentialsFile() string { return filepath.Join(p.ConfigDir, "credentials.yaml") }

// LoadKey returns the stored API key for provider, or "".
func LoadKey(p Paths, provider string) (string, error) {
	data, err := os.ReadFile(p.CredentialsFile())
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var keys map[string]string
	if err := yaml.Unmarshal(data, &keys); err != nil {
		return "", fmt.Errorf("parse %s: %w", p.CredentialsFile(), err)
	}
	return keys[provider], nil
}

// SaveKey stores an API key for provider.
func SaveKey(p Paths, provider, key string) error {
	keys := map[string]string{}
	if data, err := os.ReadFile(p.CredentialsFile()); err == nil {
		if err := yaml.Unmarshal(data, &keys); err != nil {
			return fmt.Errorf("parse %s: %w", p.CredentialsFile(), err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	keys[provider] = key
	data, err := yaml.Marshal(keys)
	if err != nil {
		return err
	}
	header := []byte("# API keys for vio's model providers. Keep this file private.\n")
	return fsutil.WriteFileAtomic(p.CredentialsFile(), append(header, data...), 0o600)
}

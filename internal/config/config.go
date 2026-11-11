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
)

// Config is the contents of config.yaml. Precedence: flags > env > file > defaults.
type Config struct {
	Provider    string        `yaml:"provider"`
	Model       string        `yaml:"model"`
	SmallModel  string        `yaml:"small_model"`
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
		Provider:    "anthropic",
		Model:       "claude-sonnet-5-5",
		SmallModel:  "claude-haiku-5-5",
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
	if v := os.Getenv("VIO_MAX_TIER"); v != "" {
		c.MaxTier = v
	}
	if err := c.Validate(); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// DefaultFile is the commented config.yaml written by `vio init`.
const DefaultFile = `# vio configuration. See specs/plan.md §5.16.
provider: anthropic          # anthropic | openai (any OpenAI-compatible endpoint)
model: claude-sonnet-5-5
small_model: claude-haiku-5-5
max_tier: change             # observe | change | dangerous — ceiling for any run
guard_window: 120s           # lockout auto-revert window (min 30s)
budget:
  max_turns: 40
  max_cost_usd: 2.00
`

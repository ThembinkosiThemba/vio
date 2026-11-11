package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/ThembinkosiThemba/vio/internal/config"
	"github.com/ThembinkosiThemba/vio/internal/llm"
)

// setup asks which model provider to use, saves the choice, and returns it.
func (a *app) setup(ctx context.Context) (config.Config, error) {
	if !a.isTTY() {
		return config.Config{}, errors.New("setup needs a terminal; or set VIO_PROVIDER, VIO_MODEL (and the provider's API key variable)")
	}
	a.pause()
	if err := a.ensureDirs(); err != nil {
		return config.Config{}, err
	}
	cfg, err := config.Load(a.paths.ConfigFile())
	if err != nil {
		cfg = config.Default()
	}
	st := newStyle(a.stdout)
	out := a.stdout

	fmt.Fprintf(out, "\n  %s\n\n", st.bold("Which model should vio use?"))
	def := 1
	for i, p := range llm.Providers {
		if p.ID == cfg.Provider {
			def = i + 1
		}
		fmt.Fprintf(out, "  %s  %s\n", st.dim(strconv.Itoa(i+1)), p.Label)
	}
	fmt.Fprintln(out)
	var info llm.ProviderInfo
	for {
		n, err := strconv.Atoi(a.ask("Provider", strconv.Itoa(def)))
		if err == nil && n >= 1 && n <= len(llm.Providers) {
			info = llm.Providers[n-1]
			break
		}
		fmt.Fprintf(out, "  %s\n", st.yellow("Pick a number from the list."))
	}

	base := info.BaseURL
	if cfg.Provider == info.ID && cfg.BaseURL != "" {
		base = cfg.BaseURL
	}
	if info.ID == "ollama" || info.ID == "openai-compatible" {
		for {
			base = a.ask("Server URL", base)
			if base != "" {
				break
			}
		}
	}

	key, keyFromEnv := "", ""
	if info.KeyEnv != "" {
		keyFromEnv = os.Getenv(info.KeyEnv)
	}
	switch {
	case keyFromEnv != "":
		fmt.Fprintf(out, "  %s\n", st.dim("Using "+info.KeyEnv+" from your environment."))
	case info.ID == "ollama":
	case info.ID == "openai-compatible":
		key = a.askSecret("API key (leave empty if none)")
	default:
		for key == "" {
			key = a.askSecret(info.Label + " API key")
		}
	}

	model := info.DefaultModel
	if cfg.Provider == info.ID && cfg.Model != "" {
		model = cfg.Model
	}
	if info.ID != "anthropic" {
		models, err := llm.ListModels(ctx, base, firstNonEmpty(key, keyFromEnv))
		switch {
		case err != nil && info.ID == "ollama":
			fmt.Fprintf(out, "  %s\n", st.yellow("Couldn't reach Ollama at "+base+". Start it with `ollama serve`; you can still finish setup."))
		case err != nil:
			fmt.Fprintf(out, "  %s\n", st.dim("Couldn't list models ("+err.Error()+"); type the model name."))
		case len(models) > 0 && len(models) <= 30:
			fmt.Fprintf(out, "\n  %s\n", st.bold("Available models"))
			for i, m := range models {
				fmt.Fprintf(out, "  %s  %s\n", st.dim(strconv.Itoa(i+1)), m)
			}
			if !slices.Contains(models, model) {
				model = models[0]
			}
			fmt.Fprintln(out)
			pick := a.ask("Model (number or name)", model)
			if n, err := strconv.Atoi(pick); err == nil && n >= 1 && n <= len(models) {
				pick = models[n-1]
			}
			model = pick
		case len(models) > 30:
			fmt.Fprintf(out, "  %s\n", st.dim(fmt.Sprintf("%d models available.", len(models))))
		}
	}
	for {
		model = a.ask("Model", model)
		if model != "" {
			break
		}
	}

	cfg.Provider, cfg.Model = info.ID, model
	cfg.BaseURL = ""
	if base != info.BaseURL {
		cfg.BaseURL = base
	}
	if err := config.Save(a.paths.ConfigFile(), cfg); err != nil {
		return cfg, err
	}
	if key != "" {
		if err := config.SaveKey(a.paths, info.ID, key); err != nil {
			return cfg, err
		}
		fmt.Fprintf(out, "\n  %s\n", st.dim("API key saved to "+a.paths.CredentialsFile()+" (readable only by you)."))
	}
	fmt.Fprintf(out, "  %s %s %s\n\n", st.green("✓"), "Using", st.bold(model+" via "+info.ID)+st.dim(". Change it any time with `vio setup`."))
	return cfg, nil
}

// ask prompts with a default value.
func (a *app) ask(label, def string) string {
	st := newStyle(a.stdout)
	if def != "" {
		fmt.Fprintf(a.stdout, "  %s %s ", label, st.dim("["+def+"]"))
	} else {
		fmt.Fprintf(a.stdout, "  %s: ", label)
	}
	line, err := a.readLine()
	line = strings.TrimSpace(line)
	if err != nil || line == "" {
		return def
	}
	return line
}

// askSecret prompts without echo.
func (a *app) askSecret(label string) string {
	fmt.Fprintf(a.stdout, "  %s: ", label)
	b, err := term.ReadPassword(int(a.stdin.Fd()))
	fmt.Fprintln(a.stdout)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// provider builds the model client from config. Key precedence: VIO_API_KEY,
// the provider's usual variable (e.g. ANTHROPIC_API_KEY), then credentials.yaml.
func (a *app) provider(cfg config.Config) (llm.Provider, error) {
	key := os.Getenv("VIO_API_KEY")
	if info, ok := llm.Lookup(cfg.Provider); ok && key == "" && info.KeyEnv != "" {
		key = os.Getenv(info.KeyEnv)
	}
	if key == "" {
		var err error
		if key, err = config.LoadKey(a.paths, cfg.Provider); err != nil {
			return nil, err
		}
	}
	return llm.New(llm.Config{Provider: cfg.Provider, Model: cfg.Model, BaseURL: cfg.BaseURL, APIKey: key})
}

func (a *app) ensureDirs() error {
	for _, d := range []string{a.paths.ConfigDir, a.paths.StateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

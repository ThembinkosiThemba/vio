package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/ThembinkosiThemba/vio/internal/config"
	"github.com/ThembinkosiThemba/vio/internal/llm"
)

// Claude models offered in the picker; any other id can be set in config.yaml.
var anthropicModels = []string{"claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1"}

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

	provider := cfg.Provider
	if provider == "" {
		provider = llm.Providers[0].ID
	}
	opts := make([]huh.Option[string], len(llm.Providers))
	for i, p := range llm.Providers {
		opts[i] = huh.NewOption(p.Label, p.ID)
	}
	fmt.Fprintln(a.stdout)
	if err := runForm(huh.NewGroup(
		huh.NewSelect[string]().
			Title("Which model provider should vio use?").
			Description("You can change this any time with /setup.").
			Options(opts...).
			Value(&provider),
	)); err != nil {
		return cfg, err
	}
	info, _ := llm.Lookup(provider)

	base := info.BaseURL
	if cfg.Provider == info.ID && cfg.BaseURL != "" {
		base = cfg.BaseURL
	}
	keyFromEnv := ""
	if info.KeyEnv != "" {
		keyFromEnv = os.Getenv(info.KeyEnv)
	}
	var key string
	var fields []huh.Field
	if info.ID == "ollama" || info.ID == "openai-compatible" {
		fields = append(fields, huh.NewInput().
			Title("Server URL").
			Description("The OpenAI-compatible endpoint, usually ending in /v1.").
			Placeholder("http://localhost:8000/v1").
			Value(&base).
			Validate(required("a URL")))
	}
	switch {
	case keyFromEnv != "":
	case info.KeyEnv != "":
		fields = append(fields, huh.NewInput().
			Title(info.Label+" API key").
			Description("Saved to "+a.paths.CredentialsFile()+", readable only by you.").
			EchoMode(huh.EchoModePassword).
			Value(&key).
			Validate(required("an API key")))
	case info.ID == "openai-compatible":
		fields = append(fields, huh.NewInput().
			Title("API key").
			Description("Leave empty if the server doesn't need one.").
			EchoMode(huh.EchoModePassword).
			Value(&key))
	}
	if len(fields) > 0 {
		if err := runForm(huh.NewGroup(fields...)); err != nil {
			return cfg, err
		}
	}

	if cfg.Model == "" || cfg.Provider != info.ID {
		cfg.Model = info.DefaultModel // the old provider's model means nothing here
	}
	cfg.Provider, cfg.BaseURL = info.ID, ""
	if base != info.BaseURL {
		cfg.BaseURL = base
	}
	if err := a.pickModel(ctx, &cfg, strings.TrimSpace(key)); err != nil {
		return cfg, err
	}
	if key != "" {
		if err := config.SaveKey(a.paths, info.ID, strings.TrimSpace(key)); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// pickModel lets the operator choose a model for cfg.Provider and saves it.
// key is a just-entered API key not yet stored.
func (a *app) pickModel(ctx context.Context, cfg *config.Config, key string) error {
	info, ok := llm.Lookup(cfg.Provider)
	if !ok {
		return fmt.Errorf("unknown provider %q", cfg.Provider)
	}
	base := cfg.BaseURL
	if base == "" {
		base = info.BaseURL
	}
	if key == "" {
		key = a.apiKey(cfg.Provider)
	}

	var models []string
	note := ""
	if info.ID == "anthropic" {
		models = anthropicModels
	} else {
		var err error
		spinWhile(a, "Looking for models at "+base, func() { models, err = llm.ListModels(ctx, base, key) })
		switch {
		case err != nil && info.ID == "ollama":
			note = "Couldn't reach Ollama at " + base + ". Start it with `ollama serve`, then type a model name."
		case err != nil:
			note = "Couldn't list models (" + err.Error() + "). Type the model name."
		case len(models) == 0 && info.ID == "ollama":
			note = "Ollama has no models yet. Pull one with `ollama pull qwen3`, then type its name."
		}
	}

	model := cfg.Model
	var field huh.Field
	if len(models) > 0 {
		if !slices.Contains(models, model) {
			model = models[0]
		}
		opts := make([]huh.Option[string], len(models))
		for i, m := range models {
			opts[i] = huh.NewOption(m, m)
		}
		field = huh.NewSelect[string]().
			Title("Model").
			Description(fmt.Sprintf("%d available. Type / to filter.", len(models))).
			Options(opts...).
			Height(min(len(models)+2, 12)).
			Value(&model)
	} else {
		desc := "The model id, e.g. qwen3 or gpt-5."
		if note != "" {
			desc = note
		}
		field = huh.NewInput().Title("Model").Description(desc).Value(&model).Validate(required("a model name"))
	}
	if err := runForm(huh.NewGroup(field)); err != nil {
		return err
	}

	cfg.Model = strings.TrimSpace(model)
	if err := config.Save(a.paths.ConfigFile(), *cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "  %s Using %s %s\n\n", sAccent.Render("✓"), sBold.Render(cfg.Model), sMuted.Render("via "+cfg.Provider))
	return nil
}

func required(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("enter " + what)
		}
		return nil
	}
}

// spinWhile shows a spinner line while fn runs (terminal only).
func spinWhile(a *app, label string, fn func()) {
	if !newStyle(a.stdout).on {
		fn()
		return
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			fmt.Fprint(a.stdout, "\r  "+sAccent.Render(frames[i%len(frames)])+" "+sMuted.Render(label))
			select {
			case <-done:
				fmt.Fprint(a.stdout, "\r\x1b[K")
				return
			case <-t.C:
			}
		}
	}()
	fn()
	close(done)
	wg.Wait()
}

// apiKey resolves a provider's key: VIO_API_KEY, the provider's usual variable
// (e.g. ANTHROPIC_API_KEY), then credentials.yaml.
func (a *app) apiKey(provider string) string {
	if k := os.Getenv("VIO_API_KEY"); k != "" {
		return k
	}
	if info, ok := llm.Lookup(provider); ok && info.KeyEnv != "" {
		if k := os.Getenv(info.KeyEnv); k != "" {
			return k
		}
	}
	k, _ := config.LoadKey(a.paths, provider)
	return k
}

// provider builds the model client from config.
func (a *app) provider(cfg config.Config) (llm.Provider, error) {
	return llm.New(llm.Config{Provider: cfg.Provider, Model: cfg.Model, BaseURL: cfg.BaseURL, APIKey: a.apiKey(cfg.Provider)})
}

func (a *app) ensureDirs() error {
	for _, d := range []string{a.paths.ConfigDir, a.paths.StateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

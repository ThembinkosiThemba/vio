package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/facts"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

const hostsUsage = `Usage: vio hosts <subcommand>

  add <name> --addr ADDR --user USER [--port N] [--identity FILE] [--tags a,b] [--notes TEXT] [--trust [--fingerprint SHA256:...]]
  ls [--json]
  rm <name>
  trust <name> [--fingerprint SHA256:...]
  check [name|group ...]
`

func (a *app) cmdHosts(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(a.stderr, hostsUsage)
		return &exitErr{exitUsage, errors.New("missing subcommand")}
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return a.hostsAdd(ctx, rest)
	case "ls", "list":
		return a.hostsList(rest)
	case "rm", "remove":
		return a.hostsRemove(rest)
	case "trust":
		return a.hostsTrust(ctx, rest)
	case "check":
		return a.hostsCheck(ctx, rest)
	case "-h", "--help", "help":
		fmt.Fprint(a.stdout, hostsUsage)
		return nil
	default:
		return usagef("unknown hosts subcommand %q", sub)
	}
}

func (a *app) loadInventory() (*inventory.Inventory, error) {
	return inventory.Load(a.paths.HostsFile())
}

func (a *app) hostKeys() transport.HostKeys {
	return transport.HostKeys{VioFile: a.paths.KnownHostsFile(), Extra: transport.DefaultExtraKnownHosts()}
}

func (a *app) hostsAdd(ctx context.Context, args []string) error {
	fs := a.newFlags("hosts add", "hosts add <name> --addr ADDR --user USER [flags]")
	var h inventory.Host
	var tags, fingerprint string
	var trust bool
	fs.StringVar(&h.Addr, "addr", "", "IP address or DNS name (required)")
	fs.StringVar(&h.User, "user", "", "SSH login user (required)")
	fs.IntVar(&h.Port, "port", 0, "SSH port (default 22)")
	fs.StringVar(&h.Identity, "identity", "", "private key file (default: ssh-agent, then ~/.ssh/id_*)")
	fs.StringVar(&tags, "tags", "", "comma-separated tags, e.g. prod,web")
	fs.StringVar(&h.Notes, "notes", "", "operator notes given to the agent as trusted context")
	fs.BoolVar(&trust, "trust", false, "verify and record the host key now")
	fs.StringVar(&fingerprint, "fingerprint", "", "expected host key fingerprint (SHA256:...) for --trust")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("hosts add: expected exactly one host name")
	}
	h.Name = pos[0]
	for _, t := range strings.Split(tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			h.Tags = append(h.Tags, t)
		}
	}

	inv, err := a.loadInventory()
	if err != nil {
		return err
	}
	if err := inv.Add(h); err != nil {
		return err
	}
	if err := inv.Save(a.paths.HostsFile()); err != nil {
		return err
	}
	args0, _ := json.Marshal(map[string]any{"addr": h.Addr, "port": h.Port, "user": h.User, "tags": h.Tags})
	if err := a.record(audit.Record{Kind: audit.KindInventory, Tool: "hosts.add", Host: h.Name, Args: args0}); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "added %s (%s@%s)\n", h.Name, h.User, h.Endpoint())

	if !trust {
		fmt.Fprintf(a.stdout, "next: vio hosts trust %s\n", h.Name)
		return nil
	}
	if err := a.trust(ctx, inv.Hosts[h.Name], fingerprint); err != nil {
		return err
	}
	return a.checkHosts(ctx, []*inventory.Host{inv.Hosts[h.Name]})
}

func (a *app) hostsList(args []string) error {
	fs := a.newFlags("hosts ls", "hosts ls [--json]")
	asJSON := fs.Bool("json", false, "output JSON")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	inv, err := a.loadInventory()
	if err != nil {
		return err
	}
	hosts := inv.All()
	if *asJSON {
		type row struct {
			Name string `json:"name"`
			*inventory.Host
		}
		rows := make([]row, len(hosts))
		for i, h := range hosts {
			rows[i] = row{h.Name, h}
		}
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	if len(hosts) == 0 {
		fmt.Fprintln(a.stdout, "no hosts yet — add one with: vio hosts add <name> --addr <ip> --user <user>")
		return nil
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tENDPOINT\tUSER\tTAGS")
	for _, h := range hosts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", h.Name, h.Endpoint(), h.User, strings.Join(h.Tags, ","))
	}
	return tw.Flush()
}

func (a *app) hostsRemove(args []string) error {
	fs := a.newFlags("hosts rm", "hosts rm <name>")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("hosts rm: expected exactly one host name")
	}
	inv, err := a.loadInventory()
	if err != nil {
		return err
	}
	if err := inv.Remove(pos[0]); err != nil {
		return err
	}
	if err := inv.Save(a.paths.HostsFile()); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "removed %s (its known_hosts entry is kept)\n", pos[0])
	return a.record(audit.Record{Kind: audit.KindInventory, Tool: "hosts.rm", Host: pos[0]})
}

func (a *app) hostsTrust(ctx context.Context, args []string) error {
	fs := a.newFlags("hosts trust", "hosts trust <name> [--fingerprint SHA256:...]")
	fingerprint := fs.String("fingerprint", "", "expected host key fingerprint; required when not on a terminal")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("hosts trust: expected exactly one host name")
	}
	inv, err := a.loadInventory()
	if err != nil {
		return err
	}
	hosts, err := inv.Resolve(pos[0])
	if err != nil {
		return err
	}
	return a.trust(ctx, hosts[0], *fingerprint)
}

// trust records a host's key after the operator verifies it, either by matching
// an expected fingerprint or by confirming on a terminal. It never replaces a
// key that is already recorded.
func (a *app) trust(ctx context.Context, h *inventory.Host, expectFP string) error {
	a.pause()
	hk := a.hostKeys()
	addr := h.Endpoint()
	key, err := transport.FetchHostKey(ctx, addr, hk.Algorithms(addr), 0)
	if err != nil {
		return err
	}
	fp := ssh.FingerprintSHA256(key)

	var unknown *transport.UnknownHostError
	switch err := hk.Check(addr, key); {
	case err == nil:
		fmt.Fprintf(a.stdout, "%s already trusted (%s %s)\n", h.Name, key.Type(), fp)
		return nil
	case !errors.As(err, &unknown):
		return err
	}

	switch {
	case expectFP != "":
		if fp != expectFP {
			return fmt.Errorf("%s presented %s %s, expected %s; refusing to trust", h.Name, key.Type(), fp, expectFP)
		}
	case a.isTTY():
		ok := a.confirm(fmt.Sprintf("Trust the SSH key of %s?", h.Name),
			fmt.Sprintf("%s presented %s %s", addr, key.Type(), fp),
			"",
			"Check it matches before trusting. In your provider's web console, run:",
			fmt.Sprintf("  ssh-keygen -lf /etc/ssh/ssh_host_%s_key.pub", keyFileType(key)))
		if !ok {
			return &exitErr{exitDeclined, errors.New("host key not trusted")}
		}
	default:
		return fmt.Errorf("%s presented %s %s; stdin is not a terminal, so pass --fingerprint to trust it", h.Name, key.Type(), fp)
	}

	if err := hk.Trust(addr, key); err != nil {
		return err
	}
	msg := key.Type() + " " + fp
	if err := a.record(audit.Record{Kind: audit.KindTrust, Tool: "hosts.trust", Host: h.Name, Msg: msg}); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "trusted %s (%s)\n", h.Name, msg)
	return nil
}

func keyFileType(k ssh.PublicKey) string {
	switch k.Type() {
	case ssh.KeyAlgoED25519:
		return "ed25519"
	case ssh.KeyAlgoRSA:
		return "rsa"
	default:
		return "ecdsa"
	}
}

func (a *app) hostsCheck(ctx context.Context, args []string) error {
	fs := a.newFlags("hosts check", "hosts check [name|group ...]")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	inv, err := a.loadInventory()
	if err != nil {
		return err
	}
	hosts, err := inv.Resolve(pos...)
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		return errors.New("no hosts in inventory")
	}
	return a.checkHosts(ctx, hosts)
}

type checkResult struct {
	host *inventory.Host
	info facts.Basic
	dur  time.Duration
	err  error
}

// checkHosts connects to each host (up to 8 at a time), gathers basic facts,
// prints one line per host in inventory order, and audits every attempt.
func (a *app) checkHosts(ctx context.Context, hosts []*inventory.Host) error {
	results := make([]checkResult, len(hosts))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = a.checkOne(ctx, h)
		}()
	}
	wg.Wait()

	failed := 0
	for _, r := range results {
		exit := 0
		msg := describe(r.info)
		if r.err != nil {
			failed++
			exit = 1
			msg = r.err.Error()
			fmt.Fprintf(a.stdout, "✗ %-12s %s\n", r.host.Name, hint(r.host, r.err))
		} else {
			fmt.Fprintf(a.stdout, "✓ %-12s %s@%s  %s  (%s)\n", r.host.Name, r.info.User, r.host.Endpoint(), msg, r.dur.Round(time.Millisecond))
		}
		if err := a.record(audit.Record{Kind: audit.KindObserve, Tool: "hosts.check", Host: r.host.Name, Msg: msg, Exit: &exit}); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d hosts failed", failed, len(results))
	}
	return nil
}

func (a *app) checkOne(ctx context.Context, h *inventory.Host) checkResult {
	start := time.Now()
	r := checkResult{host: h}
	x, err := a.dial(ctx, h)
	if err != nil {
		r.err = err
		return r
	}
	defer x.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r.info, r.err = facts.GatherBasic(ctx, x)
	r.dur = time.Since(start)
	return r
}

// dial opens a strictly host-key-verified SSH connection to h.
func (a *app) dial(ctx context.Context, h *inventory.Host) (*transport.SSH, error) {
	hk := a.hostKeys()
	cb, err := hk.Callback()
	if err != nil {
		return nil, err
	}
	cfg := transport.SSHConfig{
		Addr:              h.Endpoint(),
		User:              h.User,
		HostKeyCallback:   cb,
		HostKeyAlgorithms: hk.Algorithms(h.Endpoint()),
		Passphrase:        a.passphrase,
	}
	if h.Identity != "" {
		cfg.Identities = []string{h.Identity}
	}
	return transport.DialSSH(ctx, cfg)
}

func describe(b facts.Basic) string {
	parts := []string{}
	if b.OS != "" {
		parts = append(parts, b.OS)
	}
	if b.Kernel != "" {
		parts = append(parts, b.Kernel+" "+b.Arch)
	}
	switch {
	case b.Root:
		parts = append(parts, "root")
	case b.Sudo:
		parts = append(parts, "sudo ✓")
	default:
		parts = append(parts, "sudo ✗ (needs password or not allowed)")
	}
	return strings.Join(parts, " · ")
}

func hint(h *inventory.Host, err error) string {
	var unknown *transport.UnknownHostError
	if errors.As(err, &unknown) {
		return fmt.Sprintf("unknown host key %s %s — verify, then: vio hosts trust %s",
			unknown.Key.Type(), ssh.FingerprintSHA256(unknown.Key), h.Name)
	}
	return err.Error()
}

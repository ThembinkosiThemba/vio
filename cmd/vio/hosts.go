package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/facts"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/sshconfig"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

const hostsUsage = `Usage: vio hosts <subcommand>

  add <name> [--addr ADDR] [--user USER] [--port N] [--identity FILE] [--tags a,b] [--notes TEXT] [--trust [--fingerprint SHA256:...]]
                        details not given come from the matching Host in ~/.ssh/config
  add --local [name]    attach the machine vio runs on (same as: vio attach)
  import [--yes]        add every concrete Host in ~/.ssh/config (dry run without --yes)
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
	case "import":
		return a.hostsImport(rest)
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
	fs := a.newFlags("hosts add", "hosts add <name> [--addr ADDR --user USER] [flags] | hosts add --local [name]")
	var h inventory.Host
	var tags, fingerprint, sshConfig string
	var trust bool
	fs.BoolVar(&h.Local, "local", false, "attach the machine vio runs on (no SSH)")
	fs.StringVar(&h.Addr, "addr", "", "IP address or DNS name (default: HostName from ~/.ssh/config)")
	fs.StringVar(&h.User, "user", "", "SSH login user (default: User from ~/.ssh/config)")
	fs.IntVar(&h.Port, "port", 0, "SSH port (default: Port from ~/.ssh/config, else 22)")
	fs.StringVar(&h.Identity, "identity", "", "private key file (default: IdentityFile from ~/.ssh/config, ssh-agent, then ~/.ssh/id_*)")
	fs.StringVar(&tags, "tags", "", "comma-separated tags, e.g. prod,web")
	fs.StringVar(&h.Notes, "notes", "", "operator notes given to the agent as trusted context")
	fs.BoolVar(&trust, "trust", false, "verify and record the host key now")
	fs.StringVar(&fingerprint, "fingerprint", "", "expected host key fingerprint (SHA256:...) for --trust")
	fs.StringVar(&sshConfig, "ssh-config", "", "ssh client config to read (default ~/.ssh/config)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	switch {
	case len(pos) == 1:
		h.Name = pos[0]
	case len(pos) == 0 && h.Local:
		if h.Name, err = localName(); err != nil {
			return err
		}
	default:
		return usagef("hosts add: expected exactly one host name")
	}
	for _, t := range strings.Split(tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			h.Tags = append(h.Tags, t)
		}
	}
	source := "flags"
	switch {
	case h.Local:
		source = "local"
	case h.Addr == "" || h.User == "":
		cfg, path, err := loadSSHConfig(sshConfig)
		if err != nil {
			return err
		}
		if err := fillFromSSHConfig(&h, cfg, path); err != nil {
			return err
		}
		source = "ssh-config"
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
	if err := a.recordAdd("hosts.add", source, h); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "added %s (%s)\n", h.Name, h.Target())

	if h.Local {
		if runtime.GOOS != "linux" {
			fmt.Fprintln(a.stdout, "note: local hosts work only when vio runs on Linux")
		}
		if !trust {
			fmt.Fprintf(a.stdout, "next: vio hosts check %s\n", h.Name)
			return nil
		}
		return a.checkHosts(ctx, []*inventory.Host{inv.Hosts[h.Name]})
	}
	if !trust {
		if len(a.hostKeys().Algorithms(h.Endpoint())) > 0 {
			fmt.Fprintf(a.stdout, "its host key is already in known_hosts; next: vio hosts check %s\n", h.Name)
		} else {
			fmt.Fprintf(a.stdout, "next: vio hosts trust %s\n", h.Name)
		}
		return nil
	}
	if err := a.trust(ctx, inv.Hosts[h.Name], fingerprint); err != nil {
		return err
	}
	return a.checkHosts(ctx, []*inventory.Host{inv.Hosts[h.Name]})
}

// recordAdd audits an inventory addition. source says where its details came
// from: flags, ssh-config or local.
func (a *app) recordAdd(tool, source string, h inventory.Host) error {
	args, _ := json.Marshal(map[string]any{"source": source, "local": h.Local, "addr": h.Addr, "port": h.Port, "user": h.User, "tags": h.Tags})
	return a.record(audit.Record{Kind: audit.KindInventory, Tool: tool, Host: h.Name, Args: args})
}

// localName is this machine's short hostname, as a valid host name.
func localName() (string, error) {
	hn, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("hosts add --local: %w; pass a name", err)
	}
	name, _, _ := strings.Cut(strings.ToLower(hn), ".")
	if inventory.ValidateName(name) != nil {
		return "", usagef("hosts add --local: hostname %q is not a valid name; pass one, e.g. vio attach this-box", hn)
	}
	return name, nil
}

// loadSSHConfig reads path, or ~/.ssh/config when path is empty.
func loadSSHConfig(path string) (*sshconfig.Config, string, error) {
	if path == "" {
		p, err := sshconfig.DefaultPath()
		if err != nil {
			return nil, "", err
		}
		path = p
	}
	cfg, err := sshconfig.Load(path)
	return cfg, path, err
}

// fillFromSSHConfig fills the connection details h leaves empty from the ssh
// config's entry for h.Name, as `ssh <name>` would resolve them. Values already
// set (from flags) win. Settings vio ignores are noted on the host.
func fillFromSSHConfig(h *inventory.Host, cfg *sshconfig.Config, path string) error {
	sc, err := cfg.Lookup(h.Name)
	if err != nil {
		return err
	}
	if !sc.Known && h.Addr == "" {
		missing := []string{"--addr"}
		if h.User == "" {
			missing = append(missing, "--user")
		}
		return usagef("hosts add: %s is not a Host in %s; pass %s", h.Name, path, strings.Join(missing, " and "))
	}
	if h.Addr == "" {
		h.Addr = sc.Addr()
	}
	if h.User == "" {
		h.User = sc.User
	}
	if h.User == "" {
		// ssh logs in as the local user when the config names none.
		h.User = localUser()
	}
	if h.Port == 0 && sc.Port != 22 {
		h.Port = sc.Port
	}
	if h.Identity == "" {
		h.Identity = sc.Identity
	}
	if len(sc.Warnings) > 0 {
		h.Notes = strings.TrimSpace(h.Notes + "\n" + strings.Join(sc.Warnings, "\n"))
	}
	return nil
}

func localUser() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	// Windows reports DOMAIN\user; ssh uses only the user part.
	if _, name, ok := strings.Cut(u.Username, `\`); ok {
		return name
	}
	return u.Username
}

func (a *app) hostsImport(args []string) error {
	fs := a.newFlags("hosts import", "hosts import [--yes] [--ssh-config FILE]")
	yes := fs.Bool("yes", false, "add the hosts (default: only list them)")
	sshConfig := fs.String("ssh-config", "", "ssh client config to read (default ~/.ssh/config)")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return usagef("hosts import: takes no arguments")
	}
	cfg, path, err := loadSSHConfig(*sshConfig)
	if err != nil {
		return err
	}
	inv, err := a.loadInventory()
	if err != nil {
		return err
	}
	// Dedupe on where a host is reached too, so an alias for a server that is
	// already in the inventory under another name is not added twice.
	targets := map[string]string{}
	for _, h := range inv.All() {
		if !h.Local {
			targets[h.Target()] = h.Name
		}
	}

	var add []inventory.Host
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	for _, alias := range cfg.Aliases() {
		name := strings.ToLower(alias)
		h := inventory.Host{Name: name}
		skip := ""
		switch {
		case inventory.ValidateName(name) != nil:
			skip = "not a valid vio host name"
		case inv.Hosts[name] != nil:
			skip = "already in inventory"
		default:
			if err := fillFromSSHConfig(&h, cfg, path); err != nil {
				skip = err.Error()
			} else if other, dup := targets[h.Target()]; dup {
				skip = "same server as " + other
			} else if err := h.Validate(); err != nil {
				skip = err.Error()
			}
		}
		if skip != "" {
			fmt.Fprintf(tw, "  skip\t%s\t%s\n", alias, skip)
			continue
		}
		targets[h.Target()] = name
		add = append(add, h)
		fmt.Fprintf(tw, "  add\t%s\t%s\n", name, h.Target())
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	switch {
	case len(add) == 0:
		fmt.Fprintf(a.stdout, "nothing new to import from %s\n", path)
		return nil
	case !*yes:
		fmt.Fprintf(a.stdout, "dry run: pass --yes to add %d host(s)\n", len(add))
		return nil
	}
	for _, h := range add {
		if err := inv.Add(h); err != nil {
			return err
		}
	}
	if err := inv.Save(a.paths.HostsFile()); err != nil {
		return err
	}
	for _, h := range add {
		if err := a.recordAdd("hosts.import", "ssh-config", h); err != nil {
			return err
		}
	}
	fmt.Fprintf(a.stdout, "imported %d host(s); next: vio hosts check\n", len(add))
	return nil
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
		fmt.Fprintln(a.stdout, "no hosts yet — attach this machine with: vio attach, or add one with: vio hosts add <ssh-alias>")
		return nil
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tENDPOINT\tUSER\tTAGS")
	for _, h := range hosts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", h.Name, endpoint(h), h.User, strings.Join(h.Tags, ","))
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
	if h.Local {
		fmt.Fprintf(a.stdout, "%s is this machine; there is no SSH host key to trust\n", h.Name)
		return nil
	}
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
		// A key the operator already accepted with ssh is reused, not re-asked.
		where := ""
		if (transport.HostKeys{VioFile: hk.VioFile}).Check(addr, key) != nil {
			where = " via ~/.ssh/known_hosts"
		}
		fmt.Fprintf(a.stdout, "%s already trusted%s (%s %s)\n", h.Name, where, key.Type(), fp)
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
			fmt.Fprintf(a.stdout, "✓ %-12s %s@%s  %s  (%s)\n", r.host.Name, r.info.User, endpoint(r.host), msg, r.dur.Round(time.Millisecond))
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

// endpoint is where h is reached: host:port, or "local".
func endpoint(h *inventory.Host) string {
	if h.Local {
		return "local"
	}
	return h.Endpoint()
}

// dial opens a strictly host-key-verified SSH connection to h, or runs
// commands directly when h is the machine vio runs on.
func (a *app) dial(ctx context.Context, h *inventory.Host) (transport.Executor, error) {
	if h.Local {
		if runtime.GOOS != "linux" {
			return nil, fmt.Errorf("%s is a local host; vio can manage the machine it runs on only when that is Linux", h.Name)
		}
		return &transport.Local{}, nil
	}
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

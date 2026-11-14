package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"maps"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
)

// isolate gives the test its own vio dirs and home (with ~/.ssh), and returns
// the state dir and ~/.ssh.
func isolate(t *testing.T) (state, sshDir string) {
	t.Helper()
	t.Setenv("VIO_CONFIG_DIR", t.TempDir())
	state = t.TempDir()
	t.Setenv("VIO_STATE_DIR", state)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sshDir = filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return state, sshDir
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadHosts(t *testing.T) *inventory.Inventory {
	t.Helper()
	inv, err := inventory.Load(filepath.Join(os.Getenv("VIO_CONFIG_DIR"), "hosts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

type step struct {
	args     []string
	wantCode int
	wantOut  string // substring of stdout
	wantErr  string // substring of stderr
}

func runSteps(t *testing.T, steps []step) {
	t.Helper()
	for _, s := range steps {
		code, out, errOut := runCLI(t, s.args...)
		if code != s.wantCode {
			t.Fatalf("vio %s: exit %d, want %d\nstdout: %s\nstderr: %s", strings.Join(s.args, " "), code, s.wantCode, out, errOut)
		}
		if !strings.Contains(out, s.wantOut) || !strings.Contains(errOut, s.wantErr) {
			t.Fatalf("vio %s:\nstdout %q (want %q)\nstderr %q (want %q)", strings.Join(s.args, " "), out, s.wantOut, errOut, s.wantErr)
		}
	}
}

const sshConfig = `Host web-1
  HostName 203.0.113.10
  User deploy
  Port 2222
  IdentityFile ~/.ssh/id_web
  ProxyJump bastion

Host web-2
  HostName 203.0.113.11
  User deploy

Host Web-Caps
  HostName 203.0.113.12
  User ops

Host also-web-1
  HostName 203.0.113.10
  Port 2222
  User deploy

Host *.internal
  User ops
`

func TestCLIAddFromSSHConfig(t *testing.T) {
	_, sshDir := isolate(t)
	writeFile(t, filepath.Join(sshDir, "config"), sshConfig)

	runSteps(t, []step{
		{[]string{"hosts", "add", "web-1"}, 0, "added web-1 (deploy@203.0.113.10:2222)", ""},
		{[]string{"hosts", "add", "web-2", "--user", "root", "--port", "2200"}, 0, "added web-2 (root@203.0.113.11:2200)", ""},
		{[]string{"hosts", "add", "nope"}, 2, "", "pass --addr and --user"},
		{[]string{"hosts", "add", "nope", "--user", "root"}, 2, "", "pass --addr"},
		{[]string{"hosts", "add", "app.internal"}, 2, "", "not a Host"},
		{[]string{"hosts", "add", "flags-only", "--addr", "198.51.100.1", "--user", "u"}, 0, "added flags-only (u@198.51.100.1:22)", ""},
	})

	inv := loadHosts(t)
	w1 := inv.Hosts["web-1"]
	if w1.Identity != filepath.Join(filepath.Dir(sshDir), ".ssh", "id_web") {
		t.Errorf("identity = %q", w1.Identity)
	}
	if !strings.Contains(w1.Notes, "ProxyJump") {
		t.Errorf("notes lack the ProxyJump warning: %q", w1.Notes)
	}
}

func TestCLIImport(t *testing.T) {
	state, sshDir := isolate(t)
	writeFile(t, filepath.Join(sshDir, "config"), sshConfig)

	runSteps(t, []step{
		{[]string{"hosts", "add", "web-2", "--addr", "203.0.113.11", "--user", "deploy"}, 0, "added", ""},
		{[]string{"hosts", "import"}, 0, "dry run: pass --yes to add 2 host(s)", ""},
	})
	if n := len(loadHosts(t).Hosts); n != 1 {
		t.Fatalf("dry run wrote the inventory: %d hosts", n)
	}

	code, out, errOut := runCLI(t, "hosts", "import", "--yes")
	if code != 0 {
		t.Fatalf("import --yes: exit %d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{"add   web-1", "add   web-caps", "skip  web-2", "already in inventory", "skip  also-web-1", "same server as web-1", "imported 2 host(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("import output lacks %q:\n%s", want, out)
		}
	}
	runSteps(t, []step{{[]string{"hosts", "import", "--yes"}, 0, "nothing new to import", ""}})

	inv := loadHosts(t)
	if names := slices.Sorted(maps.Keys(inv.Hosts)); !slices.Equal(names, []string{"web-1", "web-2", "web-caps"}) {
		t.Errorf("hosts = %v", names)
	}

	recs, err := audit.ReadAll(state + "/audit.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var imported []string
	for _, r := range recs {
		if r.Tool == "hosts.import" {
			imported = append(imported, r.Host)
			var args map[string]any
			json.Unmarshal(r.Args, &args)
			if args["source"] != "ssh-config" {
				t.Errorf("import audit args = %s", r.Args)
			}
		}
	}
	if !slices.Equal(imported, []string{"web-1", "web-caps"}) {
		t.Errorf("audited imports = %v", imported)
	}
}

func TestCLIAttachLocal(t *testing.T) {
	state, _ := isolate(t)
	runSteps(t, []step{
		{[]string{"attach", "box"}, 0, "added box (local)", ""},
		{[]string{"hosts", "ls"}, 0, "local", ""},
		{[]string{"hosts", "trust", "box"}, 0, "no SSH host key to trust", ""},
		{[]string{"hosts", "add", "--local", "box2", "--addr", "203.0.113.10"}, 1, "", "local host takes no addr"},
		{[]string{"attach", "box", "extra"}, 2, "", ""},
	})
	if h := loadHosts(t).Hosts["box"]; h == nil || !h.Local {
		t.Fatalf("box = %+v", h)
	}

	code, out, errOut := runCLI(t, "hosts", "check", "box")
	if runtime.GOOS == "linux" {
		if code != 0 || !strings.Contains(out, "✓ box") {
			t.Errorf("check box: exit %d\n%s\n%s", code, out, errOut)
		}
	} else if code == 0 || !strings.Contains(out, "only when that is Linux") {
		t.Errorf("check box on %s: exit %d\n%s", runtime.GOOS, code, out)
	}

	recs, _ := audit.ReadAll(state + "/audit.jsonl")
	if len(recs) == 0 || recs[0].Tool != "hosts.add" || !strings.Contains(string(recs[0].Args), `"source":"local"`) {
		t.Errorf("first audit record = %+v", recs)
	}
}

// keyServer accepts TCP connections and completes only the SSH key exchange,
// which is all `hosts trust` needs.
func keyServer(t *testing.T) (addr string, key ssh.PublicKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				ssh.NewServerConn(c, cfg)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String(), signer.PublicKey()
}

func TestCLITrustReusesKnownHosts(t *testing.T) {
	_, sshDir := isolate(t)
	addr, key := keyServer(t)
	host, port, _ := net.SplitHostPort(addr)
	impostor, _, _ := ed25519.GenerateKey(rand.Reader)
	impostorKey, _ := ssh.NewPublicKey(impostor)

	tests := []struct {
		name     string
		recorded ssh.PublicKey
		want     step
	}{
		{"known key accepted", key, step{nil, 0, "already trusted via ~/.ssh/known_hosts", ""}},
		{"mismatched key refused", impostorKey, step{nil, 1, "", "HOST KEY MISMATCH"}},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := []string{"good", "bad"}[i]
			writeFile(t, filepath.Join(sshDir, "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, tt.recorded)+"\n")
			runSteps(t, []step{
				{[]string{"hosts", "add", name, "--addr", host, "--port", port, "--user", "u"}, 0, "already in known_hosts", ""},
				{append([]string{"hosts", "trust", name}, tt.want.args...), tt.want.wantCode, tt.want.wantOut, tt.want.wantErr},
			})
		})
	}
}

func TestCLITrustUnknownStillFails(t *testing.T) {
	isolate(t)
	addr, key := keyServer(t)
	host, port, _ := net.SplitHostPort(addr)
	runSteps(t, []step{
		{[]string{"hosts", "add", "fresh", "--addr", host, "--port", port, "--user", "u"}, 0, "next: vio hosts trust fresh", ""},
		// Not a terminal and no --fingerprint: refuse, but show the fingerprint.
		{[]string{"hosts", "trust", "fresh"}, 1, "", ssh.FingerprintSHA256(key)},
	})
}

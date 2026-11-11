package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// UnknownHostError means the host has no entry in any known_hosts file.
// It carries the presented key so the operator can verify and trust it.
type UnknownHostError struct {
	Addr string
	Key  ssh.PublicKey
}

func (e *UnknownHostError) Error() string {
	return fmt.Sprintf("unknown host key for %s (%s %s)", e.Addr, e.Key.Type(), ssh.FingerprintSHA256(e.Key))
}

// HostKeyMismatchError means the host presented a key that differs from the
// recorded one. This is either a reinstalled server or an attack; vio never
// overrides it automatically.
type HostKeyMismatchError struct {
	Addr  string
	Key   ssh.PublicKey
	Files []string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf("HOST KEY MISMATCH for %s: got %s %s, which does not match %v — possible MITM; refusing to connect",
		e.Addr, e.Key.Type(), ssh.FingerprintSHA256(e.Key), e.Files)
}

// HostKeys verifies server keys against known_hosts files. VioFile is vio's own
// file (written by Trust); Extra are read-only (typically ~/.ssh/known_hosts).
type HostKeys struct {
	VioFile string
	Extra   []string
}

// DefaultExtraKnownHosts returns ~/.ssh/known_hosts if it exists.
func DefaultExtraKnownHosts() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	p := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	return []string{p}
}

func (k HostKeys) files() []string {
	var out []string
	for _, f := range append([]string{k.VioFile}, k.Extra...) {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); err == nil {
			out = append(out, f)
		}
	}
	return out
}

func (k HostKeys) db() (ssh.HostKeyCallback, error) {
	files := k.files()
	if len(files) == 0 {
		// No known hosts at all: every host is unknown.
		return func(string, net.Addr, ssh.PublicKey) error {
			return &knownhosts.KeyError{}
		}, nil
	}
	return knownhosts.New(files...)
}

// Callback returns a strict HostKeyCallback. It never accepts an unknown key.
func (k HostKeys) Callback() (ssh.HostKeyCallback, error) {
	check, err := k.db()
	if err != nil {
		return nil, fmt.Errorf("known_hosts: %w", err)
	}
	files := k.files()
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := check(hostname, remote, key)
		var ke *knownhosts.KeyError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &ke) && len(ke.Want) == 0:
			return &UnknownHostError{Addr: hostname, Key: key}
		case errors.As(err, &ke):
			return &HostKeyMismatchError{Addr: hostname, Key: key, Files: files}
		default:
			return err
		}
	}, nil
}

// Check classifies key for addr: nil if known and matching, *UnknownHostError,
// or *HostKeyMismatchError.
func (k HostKeys) Check(addr string, key ssh.PublicKey) error {
	cb, err := k.Callback()
	if err != nil {
		return err
	}
	return cb(addr, &net.TCPAddr{}, key)
}

// Algorithms returns the host key algorithms already recorded for addr, so the
// server is asked for a key type we can verify instead of one we can't (which
// would look like a mismatch). Nil means no preference.
func (k HostKeys) Algorithms(addr string) []string {
	check, err := k.db()
	if err != nil {
		return nil
	}
	// Probe with a throwaway key: the resulting KeyError lists the known keys.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil
	}
	var ke *knownhosts.KeyError
	if err := check(addr, &net.TCPAddr{}, probe); !errors.As(err, &ke) {
		return nil
	}
	var algos []string
	for _, w := range ke.Want {
		switch t := w.Key.Type(); t {
		case ssh.KeyAlgoRSA:
			// An RSA host key can be served under any of these signature algorithms.
			algos = append(algos, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA)
		default:
			algos = append(algos, t)
		}
	}
	slices.Sort(algos)
	return slices.Compact(algos)
}

// Trust appends key for addr to vio's known_hosts file.
func (k HostKeys) Trust(addr string, key ssh.PublicKey) error {
	if k.VioFile == "" {
		return errors.New("trust: no vio known_hosts file configured")
	}
	if err := os.MkdirAll(filepath.Dir(k.VioFile), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(k.VioFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, key)
	if _, err := f.WriteString(line + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

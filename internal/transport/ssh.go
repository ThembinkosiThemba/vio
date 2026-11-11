package transport

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/ThembinkosiThemba/vio/internal/fsutil"
)

// SSHConfig describes how to reach and authenticate to one host.
type SSHConfig struct {
	Addr              string              // host:port
	User              string              // login user
	Identities        []string            // private key files; empty means ~/.ssh defaults
	HostKeyCallback   ssh.HostKeyCallback // required; use HostKeys.Callback
	HostKeyAlgorithms []string            // optional; see HostKeys.Algorithms
	// Passphrase is asked for encrypted keys. Nil skips encrypted keys.
	Passphrase     func(path string) ([]byte, error)
	Sudo           bool          // elevate file operations
	ConnectTimeout time.Duration // 0 means 15s
}

// SSH is an Executor over one SSH connection. Sessions are multiplexed on it.
// vio never requests agent forwarding, port forwarding, or X11.
type SSH struct {
	client *ssh.Client
	sudo   bool
}

// DialSSH connects and authenticates. It fails closed on any host key problem.
func DialSSH(ctx context.Context, cfg SSHConfig) (*SSH, error) {
	if cfg.HostKeyCallback == nil {
		return nil, errors.New("ssh: HostKeyCallback is required")
	}
	timeout := cfg.ConnectTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	signers, closeAgent, err := loadSigners(cfg)
	if err != nil {
		return nil, err
	}
	defer closeAgent()

	sc := &ssh.ClientConfig{
		User:              cfg.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback:   cfg.HostKeyCallback,
		HostKeyAlgorithms: cfg.HostKeyAlgorithms,
		Timeout:           timeout,
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %w", cfg.Addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, cfg.Addr, sc)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh %s: %w", cfg.Addr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &SSH{client: ssh.NewClient(c, chans, reqs), sudo: cfg.Sudo}, nil
}

var errKeyCaptured = errors.New("host key captured")

// FetchHostKey performs only the key exchange with addr and returns the host key
// the server presents, without authenticating. Pass algos (see HostKeys.Algorithms)
// to ask for a key type that is already recorded.
func FetchHostKey(ctx context.Context, addr string, algos []string, timeout time.Duration) (ssh.PublicKey, error) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	var key ssh.PublicKey
	sc := &ssh.ClientConfig{
		User:              "vio",
		HostKeyAlgorithms: algos,
		Timeout:           timeout,
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			key = k
			return errKeyCaptured
		},
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _, _, err = ssh.NewClientConn(conn, addr, sc)
	if key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("ssh %s: no host key received: %w", addr, err)
}

// loadSigners collects keys from ssh-agent (if SSH_AUTH_SOCK is set) and key files.
func loadSigners(cfg SSHConfig) ([]ssh.Signer, func(), error) {
	var signers []ssh.Signer
	closeAgent := func() {}

	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			if s, err := agent.NewClient(conn).Signers(); err == nil {
				signers = append(signers, s...)
			}
			closeAgent = func() { conn.Close() }
		}
	}

	paths, explicit := cfg.Identities, len(cfg.Identities) > 0
	if !explicit {
		paths = defaultIdentities()
	}
	for _, p := range paths {
		s, err := loadKey(fsutil.ExpandHome(p), cfg.Passphrase)
		switch {
		case err == nil:
			signers = append(signers, s)
		case explicit:
			closeAgent()
			return nil, nil, err
		}
	}
	if len(signers) == 0 {
		closeAgent()
		return nil, nil, errors.New("ssh: no credentials: set an identity in hosts.yaml or load a key into ssh-agent")
	}
	return signers, closeAgent, nil
}

func defaultIdentities() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		p := filepath.Join(home, ".ssh", n)
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func loadKey(path string, passphrase func(string) ([]byte, error)) (ssh.Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ssh key %s: %w", path, err)
	}
	s, err := ssh.ParsePrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) && passphrase != nil {
		pw, perr := passphrase(path)
		if perr != nil {
			return nil, perr
		}
		s, err = ssh.ParsePrivateKeyWithPassphrase(pem, pw)
	}
	if err != nil {
		return nil, fmt.Errorf("ssh key %s: %w", path, err)
	}
	return s, nil
}

// Run executes argv on the remote host. The remote side receives a single
// POSIX-quoted command line built by CommandLine.
func (s *SSH) Run(ctx context.Context, c Cmd) (Result, error) {
	c, err := c.withDefaults()
	if err != nil {
		return Result{}, err
	}
	sess, err := s.client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()

	stdout := &capBuffer{max: c.MaxOutput}
	stderr := &capBuffer{max: c.MaxOutput}
	sess.Stdin, sess.Stdout, sess.Stderr = c.Stdin, stdout, stderr

	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- sess.Run(CommandLine(c)) }()

	select {
	case err = <-done:
	case <-ctx.Done():
		_ = sess.Signal(ssh.SIGKILL)
		sess.Close()
		<-done
		res := Result{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), ExitCode: -1, Duration: time.Since(start)}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return res, ErrTimeout
		}
		return res, ctx.Err()
	}

	res := Result{
		Stdout:    stdout.buf.Bytes(),
		Stderr:    stderr.buf.Bytes(),
		Truncated: stdout.truncated || stderr.truncated,
		Duration:  time.Since(start),
	}
	var exitErr *ssh.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitStatus()
	default:
		return res, fmt.Errorf("ssh run: %w", err)
	}
	return res, nil
}

func (s *SSH) ReadFile(ctx context.Context, path string, max int64) ([]byte, FileInfo, error) {
	return readFile(ctx, s, s.sudo, path, max)
}

func (s *SSH) WriteFile(ctx context.Context, path string, data []byte, mode fs.FileMode) error {
	return writeFile(ctx, s, s.sudo, path, data, mode)
}

func (s *SSH) Stat(ctx context.Context, path string) (FileInfo, error) {
	return statFile(ctx, s, s.sudo, path)
}

// Close closes the underlying connection.
func (s *SSH) Close() error { return s.client.Close() }

package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// testServer is a minimal SSH server. For each "exec" it writes "exec:<command>"
// to stdout and exits 0, or exits 7 if the command contains "exit7", or hangs if
// it contains "hang".
type testServer struct {
	addr    string
	hostKey ssh.PublicKey
	keyFile string // client private key accepted by the server
}

func newKey(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, priv
}

func startServer(t *testing.T) *testServer {
	t.Helper()
	hostSigner, _ := newKey(t)
	clientSigner, clientPriv := newKey(t)

	block, err := ssh.MarshalPrivateKey(clientPriv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(k.Marshal(), clientSigner.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(hostSigner)

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
			go serveConn(c, cfg)
		}
	}()
	return &testServer{addr: ln.Addr().String(), hostKey: hostSigner.PublicKey(), keyFile: keyFile}
}

func serveConn(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range chReqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				var p struct{ Command string }
				ssh.Unmarshal(req.Payload, &p)
				req.Reply(true, nil)
				if strings.Contains(p.Command, "hang") {
					continue // never exit; the client must kill us
				}
				ch.Write([]byte("exec:" + p.Command))
				code := uint32(0)
				if strings.Contains(p.Command, "exit7") {
					code = 7
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
				ch.Close()
			}
		}()
	}
}

func dialTest(t *testing.T, srv *testServer, hk HostKeys) (*SSH, error) {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	cb, err := hk.Callback()
	if err != nil {
		t.Fatal(err)
	}
	return DialSSH(context.Background(), SSHConfig{
		Addr: srv.addr, User: "deploy", Identities: []string{srv.keyFile},
		HostKeyCallback: cb, HostKeyAlgorithms: hk.Algorithms(srv.addr),
	})
}

func TestSSHUnknownHostRefused(t *testing.T) {
	srv := startServer(t)
	hk := HostKeys{VioFile: filepath.Join(t.TempDir(), "known_hosts")}

	_, err := dialTest(t, srv, hk)
	var unknown *UnknownHostError
	if !errors.As(err, &unknown) {
		t.Fatalf("err = %v; want UnknownHostError", err)
	}
	if ssh.FingerprintSHA256(unknown.Key) != ssh.FingerprintSHA256(srv.hostKey) {
		t.Error("UnknownHostError carries the wrong key")
	}
}

func TestSSHTrustThenRun(t *testing.T) {
	srv := startServer(t)
	hk := HostKeys{VioFile: filepath.Join(t.TempDir(), "known_hosts")}

	key, err := FetchHostKey(context.Background(), srv.addr, nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var unknown *UnknownHostError
	if err := hk.Check(srv.addr, key); !errors.As(err, &unknown) {
		t.Fatalf("Check before trust = %v; want UnknownHostError", err)
	}
	if err := hk.Trust(srv.addr, key); err != nil {
		t.Fatal(err)
	}
	if err := hk.Check(srv.addr, key); err != nil {
		t.Fatalf("Check after trust = %v", err)
	}

	x, err := dialTest(t, srv, hk)
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()

	res, err := x.Run(context.Background(), Cmd{Args: []string{"echo", "a b", "$HOME"}, Sudo: true})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(res.Stdout), `exec:sudo -n -- echo 'a b' '$HOME'`; got != want {
		t.Errorf("stdout = %q; want %q", got, want)
	}

	res, err = x.Run(context.Background(), Cmd{Args: []string{"exit7"}})
	if err != nil || res.ExitCode != 7 {
		t.Errorf("exit code = %d, %v; want 7, nil", res.ExitCode, err)
	}

	start := time.Now()
	_, err = x.Run(context.Background(), Cmd{Args: []string{"hang"}, Timeout: 200 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Errorf("hang err = %v; want ErrTimeout", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("timeout took too long")
	}
}

func TestSSHHostKeyMismatchRefused(t *testing.T) {
	srv := startServer(t)
	hk := HostKeys{VioFile: filepath.Join(t.TempDir(), "known_hosts")}
	impostor, _ := newKey(t)
	if err := hk.Trust(srv.addr, impostor.PublicKey()); err != nil {
		t.Fatal(err)
	}

	_, err := dialTest(t, srv, hk)
	var mismatch *HostKeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("err = %v; want HostKeyMismatchError", err)
	}
}

func TestSSHWrongClientKeyRefused(t *testing.T) {
	srv := startServer(t)
	hk := HostKeys{VioFile: filepath.Join(t.TempDir(), "known_hosts")}
	hk.Trust(srv.addr, srv.hostKey)

	_, other := newKey(t)
	block, _ := ssh.MarshalPrivateKey(other, "")
	srv.keyFile = filepath.Join(t.TempDir(), "other")
	os.WriteFile(srv.keyFile, pem.EncodeToMemory(block), 0o600)

	if _, err := dialTest(t, srv, hk); err == nil {
		t.Fatal("dial with an unauthorized key should fail")
	}
}

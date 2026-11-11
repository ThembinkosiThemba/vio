package transport

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	tests := map[string]string{
		"ls":                   "ls",
		"/etc/ssh/sshd_config": "/etc/ssh/sshd_config",
		"":                     "''",
		"a b":                  "'a b'",
		"it's":                 `'it'\''s'`,
		"$(rm -rf /)":          "'$(rm -rf /)'",
		"x;reboot":             "'x;reboot'",
		"`id`":                 "'`id`'",
	}
	for in, want := range tests {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestCommandLineSudo(t *testing.T) {
	got := CommandLine(Cmd{Args: []string{"cat", "/etc/my file"}, Sudo: true})
	if want := "sudo -n -- cat '/etc/my file'"; got != want {
		t.Errorf("CommandLine = %q; want %q", got, want)
	}
}

func TestCapBuffer(t *testing.T) {
	b := &capBuffer{max: 5}
	n, err := b.Write([]byte("hello world"))
	if n != 11 || err != nil {
		t.Fatalf("Write = %d, %v; must report full length so the writer doesn't stall", n, err)
	}
	b.Write([]byte("more"))
	if b.buf.String() != "hello" || !b.truncated {
		t.Errorf("buf = %q truncated=%v", b.buf.String(), b.truncated)
	}
}

func TestUnixMode(t *testing.T) {
	if m := unixMode(0o040755); !m.IsDir() || m.Perm() != 0o755 {
		t.Errorf("dir mode = %v", m)
	}
	if m := unixMode(0o104755); m&fs.ModeSetuid == 0 || !m.IsRegular() {
		t.Errorf("setuid mode = %v", m)
	}
}

func TestReadFileViaFake(t *testing.T) {
	f := &Fake{Handler: func(c Cmd) (Result, error) {
		script := c.Args[2]
		switch {
		case script == statScript && c.Args[4] == "/etc/hostname":
			return Result{Stdout: []byte("6 81a4 1700000000\n")}, nil
		case script == readScript && c.Args[4] == "/etc/hostname":
			return Result{Stdout: []byte("web-1\n")}, nil
		default:
			return Result{ExitCode: exitNotExist}, nil
		}
	}}
	ctx := context.Background()

	data, info, err := f.ReadFile(ctx, "/etc/hostname", 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "web-1\n" || info.Size != 6 || info.Mode.Perm() != 0o644 {
		t.Errorf("got %q %+v", data, info)
	}

	_, _, err = f.ReadFile(ctx, "/nope", 0)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file err = %v; want ErrNotExist", err)
	}
}

func TestWriteFilePassesValuesAsArgs(t *testing.T) {
	f := &Fake{Handler: func(Cmd) (Result, error) { return Result{}, nil }, Sudo: true}
	path := "/etc/evil'; reboot; '"
	if err := f.WriteFile(context.Background(), path, []byte("data"), 0o640); err != nil {
		t.Fatal(err)
	}
	call := f.Calls[0]
	if !strings.HasPrefix(call, "sudo -n -- sh -c ") || !strings.HasSuffix(call, " 0640") {
		t.Errorf("unexpected call %q", call)
	}
	if !strings.Contains(call, Quote(path)) {
		t.Errorf("path not passed as a quoted positional arg: %q", call)
	}
	if string(f.Stdins[0]) != "data" {
		t.Errorf("stdin = %q", f.Stdins[0])
	}
	if err := f.WriteFile(context.Background(), "relative", nil, 0o600); err == nil {
		t.Error("relative path should be rejected")
	}
}

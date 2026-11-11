// Package transport runs commands and file operations on a target host, either
// locally or over SSH, behind one Executor interface.
//
// Commands are always argv. They are quoted by this package and never built from
// strings, so model- or host-supplied values cannot inject shell syntax.
package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Defaults applied when a Cmd leaves them zero.
const (
	DefaultTimeout   = 60 * time.Second
	DefaultMaxOutput = 1 << 20 // 1 MiB per stream
)

// Cmd is a command to run on the target.
type Cmd struct {
	Args      []string
	Stdin     io.Reader
	Sudo      bool          // run via `sudo -n --`
	Timeout   time.Duration // 0 means DefaultTimeout
	MaxOutput int64         // per stream; 0 means DefaultMaxOutput
}

// Result is a finished command. A non-zero ExitCode is not a Go error.
type Result struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Truncated bool
	Duration  time.Duration
}

// FileInfo describes a file on the target.
type FileInfo struct {
	Path    string
	Size    int64
	Mode    fs.FileMode
	ModTime time.Time
}

// Executor is the only way vio touches a host.
type Executor interface {
	Run(ctx context.Context, cmd Cmd) (Result, error)
	ReadFile(ctx context.Context, path string, max int64) ([]byte, FileInfo, error)
	WriteFile(ctx context.Context, path string, data []byte, mode fs.FileMode) error
	Stat(ctx context.Context, path string) (FileInfo, error)
	Close() error
}

// Elevated returns an Executor whose commands and file operations all run
// under `sudo -n`.
func Elevated(x Executor) Executor { return elevated{x} }

type elevated struct{ Executor }

func (e elevated) Run(ctx context.Context, c Cmd) (Result, error) {
	c.Sudo = true
	return e.Executor.Run(ctx, c)
}

func (e elevated) ReadFile(ctx context.Context, path string, max int64) ([]byte, FileInfo, error) {
	return readFile(ctx, e.Executor, true, path, max)
}

func (e elevated) WriteFile(ctx context.Context, path string, data []byte, mode fs.FileMode) error {
	return writeFile(ctx, e.Executor, true, path, data, mode)
}

func (e elevated) Stat(ctx context.Context, path string) (FileInfo, error) {
	return statFile(ctx, e.Executor, true, path)
}

// ErrTimeout is returned when a command exceeds its timeout.
var ErrTimeout = errors.New("command timed out")

var safeArg = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// Quote returns arg quoted for a POSIX shell.
func Quote(arg string) string {
	if arg != "" && safeArg.MatchString(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

// CommandLine renders argv (with the sudo prefix if requested) as one shell-safe string.
func CommandLine(c Cmd) string {
	args := c.Args
	if c.Sudo {
		args = append([]string{"sudo", "-n", "--"}, args...)
	}
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = Quote(a)
	}
	return strings.Join(q, " ")
}

func (c Cmd) withDefaults() (Cmd, error) {
	if len(c.Args) == 0 {
		return c, errors.New("transport: empty command")
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxOutput <= 0 {
		c.MaxOutput = DefaultMaxOutput
	}
	return c, nil
}

// capBuffer keeps the first max bytes and silently discards the rest, so a noisy
// command can't exhaust memory or stall on a full pipe.
type capBuffer struct {
	buf       bytes.Buffer
	max       int64
	truncated bool
}

func (b *capBuffer) Write(p []byte) (int, error) {
	room := b.max - int64(b.buf.Len())
	if room <= 0 {
		b.truncated = b.truncated || len(p) > 0
		return len(p), nil
	}
	if int64(len(p)) > room {
		b.buf.Write(p[:room])
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

// File operations are implemented once, as small POSIX sh scripts with all
// values passed as positional parameters, on top of any Run implementation.

type runner interface {
	Run(ctx context.Context, cmd Cmd) (Result, error)
}

// exitNotExist is the private exit code our scripts use for a missing path.
const exitNotExist = 44

const statScript = `[ -e "$1" ] || [ -L "$1" ] || exit 44; exec stat -c '%s %f %Y' -- "$1"`

func statFile(ctx context.Context, r runner, sudo bool, path string) (FileInfo, error) {
	res, err := r.Run(ctx, Cmd{Args: []string{"sh", "-c", statScript, "sh", path}, Sudo: sudo})
	if err != nil {
		return FileInfo{}, err
	}
	if res.ExitCode == exitNotExist {
		return FileInfo{}, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	if res.ExitCode != 0 {
		return FileInfo{}, cmdError("stat", path, res)
	}
	return parseStat(path, string(res.Stdout))
}

func parseStat(path, out string) (FileInfo, error) {
	f := strings.Fields(out)
	if len(f) != 3 {
		return FileInfo{}, fmt.Errorf("stat %s: unexpected output %q", path, out)
	}
	size, err1 := strconv.ParseInt(f[0], 10, 64)
	raw, err2 := strconv.ParseUint(f[1], 16, 32)
	mtime, err3 := strconv.ParseInt(f[2], 10, 64)
	if err := errors.Join(err1, err2, err3); err != nil {
		return FileInfo{}, fmt.Errorf("stat %s: %w", path, err)
	}
	return FileInfo{Path: path, Size: size, Mode: unixMode(uint32(raw)), ModTime: time.Unix(mtime, 0)}, nil
}

// unixMode converts a raw st_mode to an fs.FileMode.
func unixMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & 0o170000 {
	case 0o040000:
		mode |= fs.ModeDir
	case 0o120000:
		mode |= fs.ModeSymlink
	case 0o010000:
		mode |= fs.ModeNamedPipe
	case 0o140000:
		mode |= fs.ModeSocket
	case 0o020000:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case 0o060000:
		mode |= fs.ModeDevice
	}
	if m&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

const readScript = `[ -e "$1" ] || exit 44; exec head -c "$2" -- "$1"`

func readFile(ctx context.Context, r runner, sudo bool, path string, max int64) ([]byte, FileInfo, error) {
	if max <= 0 {
		max = DefaultMaxOutput
	}
	info, err := statFile(ctx, r, sudo, path)
	if err != nil {
		return nil, info, err
	}
	if info.Mode.IsDir() {
		return nil, info, fmt.Errorf("read %s: is a directory", path)
	}
	res, err := r.Run(ctx, Cmd{
		Args:      []string{"sh", "-c", readScript, "sh", path, strconv.FormatInt(max, 10)},
		Sudo:      sudo,
		MaxOutput: max,
	})
	if err != nil {
		return nil, info, err
	}
	if res.ExitCode == exitNotExist {
		return nil, info, &fs.PathError{Op: "read", Path: path, Err: fs.ErrNotExist}
	}
	if res.ExitCode != 0 {
		return nil, info, cmdError("read", path, res)
	}
	return res.Stdout, info, nil
}

// writeScript writes stdin to a temp file beside the target and renames it into
// place, so the target is never observed half-written.
const writeScript = `umask 077
t=$(mktemp "$1.vio.XXXXXX") || exit 1
if cat > "$t" && chmod "$2" "$t" && mv -f "$t" "$1"; then exit 0; fi
rm -f "$t"; exit 1`

func writeFile(ctx context.Context, r runner, sudo bool, path string, data []byte, mode fs.FileMode) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("write %s: path must be absolute", path)
	}
	res, err := r.Run(ctx, Cmd{
		Args:  []string{"sh", "-c", writeScript, "sh", path, fmt.Sprintf("%04o", mode.Perm())},
		Stdin: bytes.NewReader(data),
		Sudo:  sudo,
	})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return cmdError("write", path, res)
	}
	return nil
}

func cmdError(op, path string, res Result) error {
	msg := strings.TrimSpace(string(res.Stderr))
	if msg == "" {
		msg = "exit " + strconv.Itoa(res.ExitCode)
	}
	return fmt.Errorf("%s %s: %s", op, path, msg)
}

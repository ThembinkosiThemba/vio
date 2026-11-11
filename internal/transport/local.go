package transport

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"time"
)

// Local runs commands on the operator's own machine. It is only meaningful when
// the operator machine is the target (Linux); file ops rely on a POSIX sh.
type Local struct {
	// Sudo elevates file operations.
	Sudo bool
}

// Run executes argv directly, without a shell.
func (l *Local) Run(ctx context.Context, c Cmd) (Result, error) {
	c, err := c.withDefaults()
	if err != nil {
		return Result{}, err
	}
	args := c.Args
	if c.Sudo {
		args = append([]string{"sudo", "-n", "--"}, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	stdout := &capBuffer{max: c.MaxOutput}
	stderr := &capBuffer{max: c.MaxOutput}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, stdout, stderr

	start := time.Now()
	err = cmd.Run()
	res := Result{
		Stdout:    stdout.buf.Bytes(),
		Stderr:    stderr.buf.Bytes(),
		Truncated: stdout.truncated || stderr.truncated,
		Duration:  time.Since(start),
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, ErrTimeout
	}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	case err != nil:
		return res, err
	}
	return res, nil
}

func (l *Local) ReadFile(ctx context.Context, path string, max int64) ([]byte, FileInfo, error) {
	return readFile(ctx, l, l.Sudo, path, max)
}

func (l *Local) WriteFile(ctx context.Context, path string, data []byte, mode fs.FileMode) error {
	return writeFile(ctx, l, l.Sudo, path, data, mode)
}

func (l *Local) Stat(ctx context.Context, path string) (FileInfo, error) {
	return statFile(ctx, l, l.Sudo, path)
}

func (l *Local) Close() error { return nil }

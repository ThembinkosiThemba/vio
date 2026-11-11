package transport

import (
	"context"
	"io"
	"io/fs"
	"strings"
	"sync"
)

// Fake is an in-memory Executor for tests. It records every command line and
// answers from Responses (keyed by the exact CommandLine), falling back to Handler.
type Fake struct {
	mu        sync.Mutex
	Calls     []string
	Stdins    [][]byte
	Responses map[string]Result
	Handler   func(Cmd) (Result, error)
	Sudo      bool
}

// Run records the command and returns the canned or handled result.
func (f *Fake) Run(_ context.Context, c Cmd) (Result, error) {
	c, err := c.withDefaults()
	if err != nil {
		return Result{}, err
	}
	var stdin []byte
	if c.Stdin != nil {
		stdin, _ = io.ReadAll(c.Stdin)
	}
	line := CommandLine(c)

	f.mu.Lock()
	f.Calls = append(f.Calls, line)
	f.Stdins = append(f.Stdins, stdin)
	r, ok := f.Responses[line]
	h := f.Handler
	f.mu.Unlock()

	if ok {
		return r, nil
	}
	if h != nil {
		return h(c)
	}
	return Result{ExitCode: 127, Stderr: []byte("fake: no response for: " + line)}, nil
}

// CallsMatching returns recorded command lines containing substr.
func (f *Fake) CallsMatching(substr string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.Calls {
		if strings.Contains(c, substr) {
			out = append(out, c)
		}
	}
	return out
}

func (f *Fake) ReadFile(ctx context.Context, path string, max int64) ([]byte, FileInfo, error) {
	return readFile(ctx, f, f.Sudo, path, max)
}

func (f *Fake) WriteFile(ctx context.Context, path string, data []byte, mode fs.FileMode) error {
	return writeFile(ctx, f, f.Sudo, path, data, mode)
}

func (f *Fake) Stat(ctx context.Context, path string) (FileInfo, error) {
	return statFile(ctx, f, f.Sudo, path)
}

func (f *Fake) Close() error { return nil }

// Package audit implements vio's append-only, hash-chained JSONL audit log.
//
// Each line is one Record. Record.Prev is the hex SHA-256 of the previous line's
// exact bytes (empty for the first record), so editing, reordering, or deleting
// any line before the last breaks the chain and is caught by Verify.
package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Kinds of audit records. See specs/plan.md §5.13.
const (
	KindSessionStart = "session.start"
	KindSessionEnd   = "session.end"
	KindObserve      = "observe"
	KindPropose      = "propose"
	KindPolicy       = "policy"
	KindApprove      = "approve"
	KindApply        = "apply"
	KindVerify       = "verify"
	KindRollback     = "rollback"
	KindInventory    = "inventory"
	KindTrust        = "trust"
)

// Record is one audit line. Args must already be redacted by the caller.
type Record struct {
	Seq          uint64          `json:"seq"`
	TS           time.Time       `json:"ts"`
	Session      string          `json:"session"`
	Host         string          `json:"host,omitempty"`
	Kind         string          `json:"kind"`
	Tool         string          `json:"tool,omitempty"`
	Args         json.RawMessage `json:"args,omitempty"`
	Msg          string          `json:"msg,omitempty"`
	ResultDigest string          `json:"result_digest,omitempty"`
	Exit         *int            `json:"exit,omitempty"`
	Prev         string          `json:"prev"`
}

// Log appends records for one session.
type Log struct {
	path    string
	session string
	now     func() time.Time
}

// Open returns a Log writing to path with a fresh random session ID.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return &Log{path: path, session: "s-" + hex.EncodeToString(b[:]), now: time.Now}, nil
}

// Session returns this log's session ID.
func (l *Log) Session() string { return l.session }

// Append fills in Seq, TS, Session, and Prev, and writes r as one line.
func (l *Log) Append(r Record) (Record, error) {
	f, err := os.OpenFile(l.path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return r, fmt.Errorf("audit: %w", err)
	}
	defer f.Close()
	// An OS lock serialises appends across processes and is released by the
	// kernel if a process dies, so it can never go stale.
	if err := lockFile(f); err != nil {
		return r, fmt.Errorf("audit: lock: %w", err)
	}
	defer unlockFile(f)

	last, err := lastLine(f)
	if err != nil {
		return r, fmt.Errorf("audit: %w", err)
	}
	if len(last) > 0 {
		var prev Record
		if err := json.Unmarshal(last, &prev); err != nil {
			return r, fmt.Errorf("audit: last record unreadable (run `vio log --verify`): %w", err)
		}
		r.Seq = prev.Seq + 1
		r.Prev = digest(last)
	} else {
		r.Seq, r.Prev = 1, ""
	}
	r.TS = l.now().UTC()
	r.Session = l.session

	line, err := json.Marshal(r)
	if err != nil {
		return r, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return r, fmt.Errorf("audit: %w", err)
	}
	return r, f.Sync()
}

// ReadAll returns every record in the log. A missing file yields no records.
func ReadAll(path string) ([]Record, error) {
	var out []Record
	err := scan(path, func(_ []byte, r Record) error {
		out = append(out, r)
		return nil
	})
	return out, err
}

// VerifyError describes the first break in the chain.
type VerifyError struct {
	Line   int
	Reason string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("audit chain broken at line %d: %s", e.Line, e.Reason)
}

// Verify checks sequence numbers and hash links. It returns the number of
// valid records, and a *VerifyError if the chain is broken.
func Verify(path string) (int, error) {
	n := 0
	var prevLine []byte
	var prevSeq uint64
	err := scan(path, func(line []byte, r Record) error {
		n++
		want := ""
		if prevLine != nil {
			want = digest(prevLine)
		}
		if r.Prev != want {
			return &VerifyError{Line: n, Reason: "prev hash does not match previous line"}
		}
		if r.Seq != prevSeq+1 {
			return &VerifyError{Line: n, Reason: fmt.Sprintf("seq %d follows %d", r.Seq, prevSeq)}
		}
		prevLine, prevSeq = line, r.Seq
		return nil
	})
	var ve *VerifyError
	if errors.As(err, &ve) {
		return n - 1, err
	}
	return n, err
}

func scan(path string, fn func(line []byte, r Record) error) error {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return &VerifyError{Line: n, Reason: "invalid JSON"}
		}
		if err := fn(bytes.Clone(line), r); err != nil {
			return err
		}
	}
	return sc.Err()
}

func digest(line []byte) string {
	sum := sha256.Sum256(line)
	return hex.EncodeToString(sum[:])
}

// lastLine returns the final newline-terminated line of f without its newline.
func lastLine(f *os.File) ([]byte, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	if size == 0 {
		return nil, nil
	}
	// Read backwards in chunks until we find the start of the last line.
	const chunk = 64 * 1024
	var buf []byte
	for off := size; off > 0; {
		n := int64(chunk)
		if off < n {
			n = off
		}
		off -= n
		b := make([]byte, n)
		if _, err := f.ReadAt(b, off); err != nil && err != io.EOF {
			return nil, err
		}
		buf = append(b, buf...)
		trimmed := bytes.TrimRight(buf, "\n")
		if i := bytes.LastIndexByte(trimmed, '\n'); i >= 0 {
			return trimmed[i+1:], nil
		}
		if off == 0 {
			return trimmed, nil
		}
	}
	return nil, nil
}

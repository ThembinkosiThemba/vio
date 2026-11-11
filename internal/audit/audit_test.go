package audit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writeN(t *testing.T, path string, n int) {
	t.Helper()
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if _, err := l.Append(Record{Kind: KindObserve, Tool: "test", Host: "web-1"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeN(t, path, 3)
	writeN(t, path, 2) // a second session continues the same chain

	n, err := Verify(path)
	if err != nil || n != 5 {
		t.Fatalf("Verify = %d, %v; want 5, nil", n, err)
	}
	recs, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range recs {
		if r.Seq != uint64(i+1) {
			t.Errorf("record %d has seq %d", i, r.Seq)
		}
	}
	if recs[0].Prev != "" || recs[1].Prev == "" {
		t.Errorf("unexpected prev links: %q, %q", recs[0].Prev, recs[1].Prev)
	}
	if recs[0].Session == recs[4].Session {
		t.Error("separate Opens should have separate session IDs")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(lines [][]byte) [][]byte
		wantLine int
	}{
		{"edit middle line", func(l [][]byte) [][]byte {
			l[1] = bytes.Replace(l[1], []byte(`"web-1"`), []byte(`"web-2"`), 1)
			return l
		}, 3},
		{"delete middle line", func(l [][]byte) [][]byte {
			return append(l[:1], l[2:]...)
		}, 2},
		{"swap lines", func(l [][]byte) [][]byte {
			l[1], l[2] = l[2], l[1]
			return l
		}, 2},
		{"delete first line", func(l [][]byte) [][]byte {
			return l[1:]
		}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			writeN(t, path, 4)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimRight(data, "\n"), []byte("\n"))
			lines = tt.mutate(lines)
			if err := os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = Verify(path)
			var ve *VerifyError
			if !errors.As(err, &ve) {
				t.Fatalf("Verify err = %v; want VerifyError", err)
			}
			if ve.Line != tt.wantLine {
				t.Errorf("broken at line %d; want %d", ve.Line, tt.wantLine)
			}
		})
	}
}

func TestConcurrentAppendsKeepChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := Open(path)
			if err != nil {
				t.Error(err)
				return
			}
			for j := 0; j < 25; j++ {
				if _, err := l.Append(Record{Kind: KindObserve}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	n, err := Verify(path)
	if err != nil || n != 200 {
		t.Fatalf("Verify = %d, %v; want 200 records and an intact chain", n, err)
	}
}

func TestStaleLockFileIsIgnored(t *testing.T) {
	// Older versions used a sidecar .lock file; a leftover one must not block.
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	os.WriteFile(path+".lock", nil, 0o600)
	writeN(t, path, 1)
}

func TestVerifyMissingFile(t *testing.T) {
	n, err := Verify(filepath.Join(t.TempDir(), "nope.jsonl"))
	if n != 0 || err != nil {
		t.Fatalf("Verify = %d, %v; want 0, nil", n, err)
	}
}

func TestAppendRefusesCorruptTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeN(t, path, 1)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("{not json\n")
	f.Close()

	l, _ := Open(path)
	if _, err := l.Append(Record{Kind: KindObserve}); err == nil {
		t.Fatal("Append after corrupt tail should fail")
	}
}

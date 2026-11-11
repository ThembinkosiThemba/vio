//go:build !windows

package audit

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive advisory lock on f, waiting for other holders.
// The kernel releases it automatically if the process exits.
func lockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX) }

func unlockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_UN) }

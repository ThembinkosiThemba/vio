//go:build windows

package audit

import (
	"os"

	"golang.org/x/sys/windows"
)

// The lock covers one byte far past the end of the file. Windows locks are
// mandatory, so locking real data would block other processes reading the log.
const lockOffsetHigh = 0x7fffffff

// lockFile takes an exclusive OS lock on f, waiting for other holders.
// Windows releases it automatically if the process exits.
func lockFile(f *os.File) error {
	ol := &windows.Overlapped{OffsetHigh: lockOffsetHigh}
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol)
}

func unlockFile(f *os.File) error {
	ol := &windows.Overlapped{OffsetHigh: lockOffsetHigh}
	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, ol)
}

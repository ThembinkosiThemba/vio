// Package version reports build information for the vio binary.
package version

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set at release time via -ldflags "-X github.com/ThembinkosiThemba/vio/internal/version.Version=...".
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// String returns a one-line human-readable version.
func String() string {
	commit, date := Commit, Date
	if commit == "" || date == "" {
		// Fall back to VCS info stamped by `go build` for source builds.
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if commit == "" {
						commit = s.Value
					}
				case "vcs.time":
					if date == "" {
						date = s.Value
					}
				}
			}
		}
	}
	if len(commit) > 12 {
		commit = commit[:12]
	}
	if commit == "" {
		commit = "unknown"
	}
	s := fmt.Sprintf("vio %s (%s", Version, commit)
	if date != "" {
		s += ", " + date
	}
	return s + fmt.Sprintf(", %s, %s/%s)", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

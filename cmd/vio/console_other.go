//go:build !windows

package main

import "os"

// enableVT is a no-op: Unix terminals understand ANSI escapes.
func enableVT(*os.File) bool { return true }

package main

import (
	"io"
	"os"

	"golang.org/x/term"
)

// colorTerminal reports whether w is an interactive terminal that can show
// colour and redraw lines (spinners). It also enables ANSI handling on Windows.
func colorTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	return enableVT(f)
}

// termSize reports the terminal's width and height.
func termSize(f *os.File) (int, int, error) { return term.GetSize(int(f.Fd())) }

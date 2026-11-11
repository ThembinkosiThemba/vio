package main

import (
	"io"
	"os"

	"golang.org/x/term"
)

// style adds ANSI colour when writing to a terminal (and NO_COLOR is unset).
type style struct{ on bool }

func newStyle(w io.Writer) style {
	f, ok := w.(*os.File)
	if !ok || os.Getenv("NO_COLOR") != "" || !term.IsTerminal(int(f.Fd())) {
		return style{}
	}
	return style{on: enableVT(f)}
}

func (s style) wrap(code, text string) string {
	if !s.on || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s style) bold(t string) string   { return s.wrap("1", t) }
func (s style) dim(t string) string    { return s.wrap("2", t) }
func (s style) red(t string) string    { return s.wrap("31", t) }
func (s style) green(t string) string  { return s.wrap("32", t) }
func (s style) yellow(t string) string { return s.wrap("33", t) }

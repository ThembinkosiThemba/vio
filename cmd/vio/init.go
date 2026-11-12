package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/ThembinkosiThemba/vio/internal/audit"
	"github.com/ThembinkosiThemba/vio/internal/config"
	"github.com/ThembinkosiThemba/vio/internal/fsutil"
	"github.com/ThembinkosiThemba/vio/internal/inventory"
	"github.com/ThembinkosiThemba/vio/internal/policy"
)

func (a *app) cmdInit(args []string) error {
	fs := a.newFlags("init", "init")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	for _, d := range []string{a.paths.ConfigDir, a.paths.StateDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	files := []struct{ path, content string }{
		{a.paths.ConfigFile(), config.DefaultFile},
		{a.paths.HostsFile(), inventory.Skeleton},
		{a.paths.PolicyFile(), policy.Skeleton},
	}
	if err := os.MkdirAll(a.paths.RunbooksDir(), 0o700); err != nil {
		return err
	}
	for _, f := range files {
		created, err := writeIfMissing(f.path, f.content)
		if err != nil {
			return err
		}
		state := "exists "
		if created {
			state = "created"
		}
		fmt.Fprintf(a.stdout, "%s  %s\n", state, f.path)
	}
	fmt.Fprintf(a.stdout, "state    %s\n", a.paths.StateDir)
	fmt.Fprintln(a.stdout, "\nNext: vio hosts add <name> --addr <ip> --user <user> --trust")
	return a.record(audit.Record{Kind: audit.KindInventory, Tool: "init", Msg: a.paths.ConfigDir})
}

func writeIfMissing(path, content string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, fsutil.WriteFileAtomic(path, []byte(content), 0o600)
}

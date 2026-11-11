package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ThembinkosiThemba/vio/internal/audit"
)

func (a *app) cmdLog(args []string) error {
	fs := a.newFlags("log", "log [--verify] [-n N] [--json]")
	verify := fs.Bool("verify", false, "verify the hash chain")
	n := fs.Int("n", 20, "show the last N records (0 for all)")
	asJSON := fs.Bool("json", false, "print raw JSON lines")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	path := a.paths.AuditFile()

	if *verify {
		count, err := audit.Verify(path)
		if err != nil {
			return fmt.Errorf("%s: %w (%d records before the break are intact)", path, err, count)
		}
		fmt.Fprintf(a.stdout, "ok: %d records, hash chain intact (%s)\n", count, path)
		return nil
	}

	recs, err := audit.ReadAll(path)
	if err != nil {
		return err
	}
	if *n > 0 && len(recs) > *n {
		recs = recs[len(recs)-*n:]
	}
	if len(recs) == 0 {
		fmt.Fprintf(a.stdout, "audit log is empty (%s)\n", path)
		return nil
	}
	if *asJSON {
		enc := json.NewEncoder(a.stdout)
		for _, r := range recs {
			if err := enc.Encode(r); err != nil {
				return err
			}
		}
		return nil
	}
	for _, r := range recs {
		status := ""
		if r.Exit != nil {
			status = "ok"
			if *r.Exit != 0 {
				status = fmt.Sprintf("exit %d", *r.Exit)
			}
		}
		fmt.Fprintf(a.stdout, "#%-5d %s  %-13s %-10s %-12s %-6s %s\n",
			r.Seq, r.TS.Local().Format(time.DateTime), r.Kind, dash(r.Host), dash(r.Tool), status, r.Msg)
	}
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

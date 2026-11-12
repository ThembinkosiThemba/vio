// Package guard is vio's lockout dead-man switch. Before an access-affecting
// change, vio uploads a revert script and schedules it on the host itself. If a
// fresh SSH login works after the change, vio disarms it; if vio loses the
// host, the host reverts on its own when the window expires. See specs/plan.md §5.11.
package guard

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ThembinkosiThemba/vio/internal/plan"
	"github.com/ThembinkosiThemba/vio/internal/transport"
)

// Dir holds guard state on the host.
const Dir = "/var/lib/vio/guards"

// MinWindow is the shortest allowed guard window.
const MinWindow = 30 * time.Second

// Guard is an armed dead-man switch.
type Guard struct {
	ID      string
	Window  time.Duration
	Systemd bool
	dir     string
}

// Unit is the transient systemd unit name.
func (g *Guard) Unit() string { return "vio-guard-" + g.ID }

// Arm uploads script and schedules it to run after window. x must run as root.
func Arm(ctx context.Context, x transport.Executor, id, script string, window time.Duration, systemd bool) (*Guard, error) {
	if window < MinWindow {
		window = MinWindow
	}
	g := &Guard{ID: id, Window: window, Systemd: systemd, dir: Dir + "/" + id}
	if err := run(ctx, x, "mkdir", "-p", "-m", "700", "--", g.dir); err != nil {
		return nil, fmt.Errorf("guard: %w", err)
	}
	if err := x.WriteFile(ctx, g.dir+"/revert.sh", []byte(script), 0o700); err != nil {
		return nil, fmt.Errorf("guard: upload revert script: %w", err)
	}
	secs := strconv.Itoa(int(window.Seconds()))
	var err error
	if systemd {
		err = run(ctx, x, "systemd-run", "--quiet", "--unit="+g.Unit(), "--on-active="+secs+"s",
			"--timer-property=AccuracySec=1s", "/bin/sh", g.dir+"/revert.sh")
	} else {
		// Without systemd: a detached sleeper in its own session, so it outlives
		// the SSH connection. Its pid is kept for disarming.
		const bg = `setsid sh -c 'sleep "$1"; exec sh "$2"' sh "$1" "$2" </dev/null >/dev/null 2>&1 & echo $! > "$3"`
		err = run(ctx, x, "sh", "-c", bg, "sh", secs, g.dir+"/revert.sh", g.dir+"/pid")
	}
	if err != nil {
		_ = run(ctx, x, "rm", "-rf", "--", g.dir)
		return nil, fmt.Errorf("guard: schedule: %w", err)
	}
	return g, nil
}

// Disarm cancels the scheduled revert and removes the guard's files.
func (g *Guard) Disarm(ctx context.Context, x transport.Executor) error {
	var err error
	if g.Systemd {
		err = run(ctx, x, "systemctl", "stop", g.Unit()+".timer")
	} else {
		err = run(ctx, x, "sh", "-c", `kill "$(cat "$1")" 2>/dev/null; true`, "sh", g.dir+"/pid")
	}
	if err != nil {
		return fmt.Errorf("guard: disarm %s: %w", g.ID, err)
	}
	return run(ctx, x, "rm", "-rf", "--", g.dir)
}

// Reverted reports whether the host ran the revert script.
func Reverted(ctx context.Context, x transport.Executor, id string) bool {
	res, err := x.Run(ctx, transport.Cmd{Args: []string{"test", "-e", Dir + "/" + id + "/reverted"}})
	return err == nil && res.ExitCode == 0
}

func run(ctx context.Context, x transport.Executor, args ...string) error {
	res, err := x.Run(ctx, transport.Cmd{Args: args})
	if err != nil {
		return err
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s: exit %d: %s", args[0], res.ExitCode, strings.TrimSpace(string(res.Stderr)))
	}
	return nil
}

// BackupScript copies each path ("$2"...) into directory "$1" as 1, 2, ...,
// or records that it was absent. Values are positional parameters, never
// spliced into the script.
const BackupScript = `set -e; umask 077; d="$1"; shift; mkdir -p -- "$d"; i=0
for p in "$@"; do i=$((i+1))
  if [ -e "$p" ] || [ -L "$p" ]; then cp -a -- "$p" "$d/$i"; else : > "$d/$i.absent"; fi
done`

// restoreBody puts the paths "$2"... back from directory "$1", as saved by
// BackupScript. It keeps going on errors and leaves the status in rrc.
const restoreBody = `d="$1"; shift; i=0; rrc=0
for p in "$@"; do i=$((i+1))
  if [ -e "$d/$i.absent" ]; then rm -rf -- "$p" || rrc=1
  elif [ -e "$d/$i" ] || [ -L "$d/$i" ]; then rm -rf -- "$p" && cp -a -- "$d/$i" "$p" || rrc=1
  else rrc=1; fi
done`

// RestoreScript is restoreBody as a standalone `sh -c` script.
const RestoreScript = restoreBody + "\nexit $rrc"

const restoreFunc = "restore() {\n" + restoreBody + "\nreturn $rrc; }"

// RevertScript returns a self-contained POSIX sh script that undoes a: it
// restores backed-up files from backupDir, then runs the rollback commands.
// Every value is quoted with transport.Quote. If guardID is set, the script
// leaves a marker so vio can confirm the host reverted itself.
func RevertScript(a plan.Action, backupDir, guardID string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#!/bin/sh\n# vio: revert %s (%s) on %s\n%s\nrc=0\n", a.ID, a.Tool, a.Host, restoreFunc)
	if a.Rollback != nil && len(a.Rollback.Restore) > 0 {
		b.WriteString("restore " + transport.Quote(backupDir))
		for _, p := range a.Rollback.Restore {
			b.WriteString(" " + transport.Quote(p))
		}
		b.WriteString(" || rc=1\n")
	}
	if a.Rollback != nil {
		for _, c := range a.Rollback.Commands {
			b.WriteString(transport.CommandLine(transport.Cmd{Args: c}) + " || rc=1\n")
		}
	}
	if guardID != "" {
		fmt.Fprintf(&b, "touch %s\n", transport.Quote(Dir+"/"+guardID+"/reverted"))
	}
	b.WriteString("exit $rc\n")
	return b.String()
}

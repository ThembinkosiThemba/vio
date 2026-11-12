package plan

import (
	"fmt"
	"strings"
)

// maxDiffLines bounds the LCS table; larger files get a summary instead.
const maxDiffLines = 4000

// Diff returns a unified diff (3 lines of context) between before and after,
// or "" if they are equal.
func Diff(path, before, after string) string {
	if before == after {
		return ""
	}
	a, b := splitLines(before), splitLines(after)
	if len(a) > maxDiffLines || len(b) > maxDiffLines {
		return fmt.Sprintf("--- %s\n+++ %s\n(file too large to diff: %d → %d lines)\n", path, path, len(a), len(b))
	}
	ops := lcsOps(a, b)

	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", path, path)
	const ctx = 3
	for i := 0; i < len(ops); {
		if ops[i].kind == ' ' {
			i++
			continue
		}
		// Grow a hunk around this change, merging changes closer than 2*ctx.
		start := max(0, i-ctx)
		end := i
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < len(ops) && ops[run].kind == ' ' {
				run++
			}
			if run == len(ops) || run-end > 2*ctx {
				end = min(len(ops), end+ctx)
				break
			}
			end = run
		}
		aStart, bStart, aN, bN := ops[start].ai, ops[start].bi, 0, 0
		for _, o := range ops[start:end] {
			if o.kind != '+' {
				aN++
			}
			if o.kind != '-' {
				bN++
			}
		}
		fmt.Fprintf(&out, "@@ -%d,%d +%d,%d @@\n", aStart+1, aN, bStart+1, bN)
		for _, o := range ops[start:end] {
			out.WriteByte(o.kind)
			out.WriteString(o.text)
			out.WriteByte('\n')
		}
		i = end
	}
	return out.String()
}

type op struct {
	kind   byte // ' ', '-', '+'
	text   string
	ai, bi int // line index in a and b where this op sits
}

func lcsOps(a, b []string) []op {
	n, m := len(a), len(b)
	// dp[i][j] = LCS length of a[i:], b[j:]
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	var ops []op
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			ops = append(ops, op{' ', a[i], i, j})
			i++
			j++
		case j < m && (i == n || dp[i][j+1] >= dp[i+1][j]):
			ops = append(ops, op{'+', b[j], i, j})
			j++
		default:
			ops = append(ops, op{'-', a[i], i, j})
			i++
		}
	}
	return ops
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

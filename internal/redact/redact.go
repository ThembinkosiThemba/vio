// Package redact masks secrets in text before it reaches a model or the audit log.
//
// Each secret is replaced with [REDACTED:<kind>:<hash8>]. The hash lets the model
// tell two secrets apart, and refer to one, without ever seeing it.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"regexp"
	"strings"
)

type rule struct {
	kind string
	re   *regexp.Regexp
	// group is the submatch holding the secret; 0 means the whole match.
	group int
}

var rules = []rule{
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`), 0},
	{"aws_access_key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), 0},
	{"github_token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b`), 0},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`), 0},
	{"slack_token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`), 0},
	{"api_key", regexp.MustCompile(`\bsk-(?:ant-|proj-|or-)?[A-Za-z0-9_-]{20,}\b`), 0},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), 0},
	{"stripe_key", regexp.MustCompile(`\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b`), 0},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`), 0},
	// scheme://user:password@host — keep the user, hide the password.
	{"url_password", regexp.MustCompile(`\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@`), 1},
	// NAME=value / NAME: value where NAME looks secret.
	{"secret_value", regexp.MustCompile(`(?i)\b[A-Z0-9_.-]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|AUTH)[A-Z0-9_.-]*["']?\s*[:=]\s*["']?([^\s"'#,;]{4,})`), 1},
}

// String returns s with every detected secret replaced.
func String(s string) string {
	for _, r := range rules {
		s = replace(s, r)
	}
	return s
}

func replace(s string, r rule) string {
	idx := r.re.FindAllStringSubmatchIndex(s, -1)
	if idx == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		start, end := m[2*r.group], m[2*r.group+1]
		if start < 0 {
			continue
		}
		secret := s[start:end]
		if strings.HasPrefix(secret, "[REDACTED:") {
			continue // already masked by an earlier rule
		}
		b.WriteString(s[last:start])
		b.WriteString(token(r.kind, secret))
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

func token(kind, secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return "[REDACTED:" + kind + ":" + hex.EncodeToString(sum[:4]) + "]"
}

// Forbidden reports whether a file must never be read into a model's context,
// with a reason. Redaction can't make these safe: the whole file is the secret.
func Forbidden(p string) (bool, string) {
	clean := path.Clean(p)
	base := path.Base(clean)
	switch {
	case clean == "/etc/shadow" || clean == "/etc/gshadow" || clean == "/etc/shadow-" || clean == "/etc/gshadow-":
		return true, "password hashes"
	case strings.HasPrefix(clean, "/etc/ssh/") && strings.HasPrefix(base, "ssh_host_") && strings.HasSuffix(base, "_key"):
		return true, "SSH host private key"
	case strings.Contains(clean, "/.ssh/") && strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub"):
		return true, "SSH private key"
	case strings.HasPrefix(clean, "/etc/ssl/private/"):
		return true, "TLS private key"
	}
	return false, ""
}

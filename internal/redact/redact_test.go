package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStringMasksSecrets(t *testing.T) {
	tests := []struct {
		name, in, leak, keep string
	}{
		{"pem key", "a\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\nz", "b3BlbnNzaC1rZXk", "z"},
		{"aws", "key AKIAIOSFODNN7EXAMPLE here", "AKIAIOSFODNN7EXAMPLE", "here"},
		{"github", "token=ghp_" + strings.Repeat("a", 36), "ghp_aaaa", "token="},
		{"anthropic", "ANTHROPIC_API_KEY=sk-ant-api03-" + strings.Repeat("x", 30), "sk-ant-api03", "ANTHROPIC_API_KEY="},
		{"jwt", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "eyJzdWIi", "Bearer"},
		{"url password", "DATABASE_URL=postgres://app:hunter22@db:5432/app", "hunter22", "postgres://app:"},
		{"env assignment", "DB_PASSWORD=correcthorse\nPORT=8080", "correcthorse", "PORT=8080"},
		{"shadow", "root:$6$rounds=5000$abcdefgh$" + strings.Repeat("a", 40) + ":19000:0:99999:7:::", "abcdefgh", "root:"},
		{"yescrypt", "deploy:$y$j9T$F5Jx5fExrKuPp53xLKQ..1$X3DX6M94c7o.9agCG9G317fhZg9SqC.5i5rd.RhAtQ7:19000::::::", "F5Jx5fExr", "deploy:"},
		{"yaml", "  client_secret: \"s3cr3t-value\"\n  name: web", "s3cr3t-value", "name: web"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := String(tt.in)
			if strings.Contains(out, tt.leak) {
				t.Errorf("secret leaked: %q", out)
			}
			if !strings.Contains(out, tt.keep) {
				t.Errorf("non-secret context lost: %q", out)
			}
			if !strings.Contains(out, "[REDACTED:") {
				t.Errorf("no redaction marker: %q", out)
			}
		})
	}
}

func TestStringLeavesOrdinaryTextAlone(t *testing.T) {
	for _, s := range []string{
		"Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   12G   26G  32% /",
		"PasswordAuthentication no\nPermitRootLogin prohibit-password",
		"tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=812,fd=3))",
	} {
		if got := String(s); got != s {
			t.Errorf("changed ordinary text:\n in: %q\nout: %q", s, got)
		}
	}
}

func TestStableHash(t *testing.T) {
	a := String("TOKEN=abcdef123")
	b := String("TOKEN=abcdef123")
	c := String("TOKEN=zzzzzz999")
	if a != b || a == c {
		t.Errorf("hashes should be stable per secret and differ across secrets: %q %q %q", a, b, c)
	}
}

func TestForbidden(t *testing.T) {
	for p, want := range map[string]bool{
		"/etc/shadow":                       true,
		"/etc/ssh/ssh_host_ed25519_key":     true,
		"/etc/ssh/ssh_host_ed25519_key.pub": false,
		"/home/deploy/.ssh/id_rsa":          true,
		"/home/deploy/.ssh/id_rsa.pub":      false,
		"/root/.ssh/authorized_keys":        false,
		"/etc/ssl/private/site.key":         true,
		"/etc/nginx/nginx.conf":             false,
		"/etc/../etc/shadow":                true,
	} {
		if got, _ := Forbidden(p); got != want {
			t.Errorf("Forbidden(%q) = %v; want %v", p, got, want)
		}
	}
}

func TestJSON(t *testing.T) {
	in := []byte(`{"path":"/srv/.env","content":"API_KEY=sk-ant-api03-` + strings.Repeat("x", 30) + `"}`)
	out := JSON(in)
	if strings.Contains(string(out), "sk-ant") || !json.Valid(out) {
		t.Errorf("JSON = %s", out)
	}
}

package agent

import (
	"slices"
	"strings"
	"testing"
)

func TestCheckCommand(t *testing.T) {
	ok := [][]string{
		{"df", "-h"},
		{"ss", "-tlnp"},
		{"systemctl", "status", "nginx"},
		{"systemctl", "--failed"},
		{"journalctl", "-u", "nginx", "-n", "200"},
		{"tail", "-n", "100", "/var/log/auth.log"},
		{"find", "/etc", "-name", "*.conf"},
		{"ip", "addr"},
		{"ip", "route", "show"},
		{"docker", "ps", "-a"},
		{"docker", "stats", "--no-stream"},
		{"docker", "compose", "ps"},
		{"apt", "list", "--upgradable"},
		{"sshd", "-T"},
		{"ufw", "status", "verbose"},
		{"iptables", "-n", "-L"},
		{"nft", "list", "ruleset"},
		{"top", "-b", "-n", "1"},
		{"crontab", "-l"},
		{"service", "nginx", "status"},
	}
	for _, argv := range ok {
		if err := CheckCommand(argv); err != nil {
			t.Errorf("CheckCommand(%v) = %v; want allowed", argv, err)
		}
	}

	bad := [][]string{
		{},
		{"rm", "-rf", "/"},
		{"/bin/ls"},
		{"bash", "-c", "id"},
		{"systemctl", "restart", "nginx"},
		{"systemctl", "stop", "sshd"},
		{"journalctl", "--vacuum-time=1d"},
		{"journalctl", "-f"},
		{"tail", "-f", "/var/log/syslog"},
		{"find", "/", "-delete"},
		{"find", "/", "-exec", "rm", "{}", ";"},
		{"ip", "link", "set", "eth0", "down"},
		{"ip", "route", "add", "default", "via", "1.2.3.4"},
		{"docker", "rm", "-f", "web"},
		{"docker", "exec", "web", "sh"},
		{"docker", "stats"},
		{"apt", "install", "nginx"},
		{"apt", "upgrade"},
		{"dpkg", "-i", "x.deb"},
		{"ufw", "disable"},
		{"iptables", "-F"},
		{"nft", "flush", "ruleset"},
		{"crontab", "-r"},
		{"date", "-s", "2020-01-01"},
		{"top"},
		{"ls", "a\nb"},
		{"env"},
	}
	for _, argv := range bad {
		if err := CheckCommand(argv); err == nil {
			t.Errorf("CheckCommand(%v) allowed; want rejected", argv)
		}
	}
}

func TestWithDefaults(t *testing.T) {
	got := withDefaults([]string{"journalctl", "-u", "nginx"})
	if !slices.Equal(got, []string{"journalctl", "--no-pager", "-u", "nginx"}) {
		t.Errorf("got %v", got)
	}
	got = withDefaults([]string{"df", "-h"})
	if strings.Join(got, " ") != "df -h" {
		t.Errorf("got %v", got)
	}
}

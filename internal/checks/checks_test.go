package checks

import (
	"encoding/json"
	"testing"

	"github.com/ThembinkosiThemba/vio/internal/facts"
	"github.com/ThembinkosiThemba/vio/internal/tools"
)

func TestFixesOrderSafely(t *testing.T) {
	h := &tools.Host{Facts: facts.Facts{SSHPort: 2222}}
	fs := []Finding{
		{Status: Fail, Fix: fix("sshd_set", map[string]any{"settings": map[string]string{"PermitRootLogin": "no"}})},
		{Status: Fail, Fix: fix("fw_enable", map[string]any{})},
		{Status: Pass, Fix: fix("autoupdates_enable", map[string]any{})},
		{Status: Fail, Fix: fix("sshd_set", map[string]any{"settings": map[string]string{"PasswordAuthentication": "no"}})},
	}
	got := Fixes(h, fs)
	if len(got) != 3 || got[0].Tool != "sshd_set" || got[1].Tool != "fw_allow" || got[2].Tool != "fw_enable" {
		t.Fatalf("Fixes = %+v", got)
	}
	var sshd struct{ Settings map[string]string }
	json.Unmarshal(got[0].Args, &sshd)
	if len(sshd.Settings) != 2 {
		t.Errorf("sshd settings should merge: %v", sshd.Settings)
	}
	var allow struct{ Port int }
	json.Unmarshal(got[1].Args, &allow)
	if allow.Port != 2222 {
		t.Errorf("must allow the operator's SSH port, got %d", allow.Port)
	}
}

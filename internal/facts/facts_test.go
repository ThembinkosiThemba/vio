package facts

import (
	"context"
	"testing"

	"github.com/ThembinkosiThemba/vio/internal/transport"
)

func TestGatherBasic(t *testing.T) {
	osRelease := "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n# comment\nID=ubuntu\n"
	f := &transport.Fake{
		Responses: map[string]transport.Result{
			"uname -rm":       {Stdout: []byte("6.8.0-45-generic x86_64\n")},
			"id -un":          {Stdout: []byte("deploy\n")},
			"id -u":           {Stdout: []byte("1000\n")},
			"sudo -n -- true": {ExitCode: 1},
		},
		Handler: func(c transport.Cmd) (transport.Result, error) {
			if len(c.Args) > 4 && c.Args[4] == "/etc/os-release" {
				if len(c.Args) == 5 { // stat script: sh -c SCRIPT sh PATH
					return transport.Result{Stdout: []byte("80 81a4 1700000000")}, nil
				}
				return transport.Result{Stdout: []byte(osRelease)}, nil // read
			}
			return transport.Result{ExitCode: 127}, nil
		},
	}
	b, err := GatherBasic(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	want := Basic{OS: "Ubuntu 24.04.1 LTS", Kernel: "6.8.0-45-generic", Arch: "x86_64", User: "deploy"}
	if b != want {
		t.Errorf("GatherBasic = %+v; want %+v", b, want)
	}
}

func TestParseOSRelease(t *testing.T) {
	m := ParseOSRelease("ID=debian\nVERSION_ID='12'\nbad line\n")
	if m["ID"] != "debian" || m["VERSION_ID"] != "12" || len(m) != 2 {
		t.Errorf("got %v", m)
	}
}

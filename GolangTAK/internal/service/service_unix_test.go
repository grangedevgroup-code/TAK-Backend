//go:build unix

package service

import (
	"strings"
	"testing"
)

func testConfig() Config {
	return Config{Name: "golangtak", DisplayName: "GolangTAK", Description: "GolangTAK server", Executable: "/opt/Golang TAK/golangtak", Args: []string{"run", "--service", "--data", "/var/lib/golangtak"}}
}

func TestSystemdUnit(t *testing.T) {
	u := systemdUnit(testConfig())
	for _, want := range []string{"ExecStart='/opt/Golang TAK/golangtak' run --service --data /var/lib/golangtak", "Restart=always", "WantedBy=multi-user.target", "After=network-online.target", "StartLimitIntervalSec=0"} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit lacks %q:\n%s", want, u)
		}
	}
}

func TestOtherServiceFiles(t *testing.T) {
	c := testConfig()
	if p := plist(c); !strings.Contains(p, "<key>RunAtLoad</key><true/>") || !strings.Contains(p, "<key>KeepAlive</key><true/>") || !strings.Contains(p, "<string>/opt/Golang TAK/golangtak</string>") {
		t.Fatalf("plist:\n%s", p)
	}
	if o := openrcScript(c); !strings.Contains(o, "supervisor=supervise-daemon") || !strings.Contains(o, "respawn_max=0") {
		t.Fatalf("openrc:\n%s", o)
	}
	if s := sysvScript(c); !strings.Contains(s, "'/opt/Golang TAK/golangtak' supervise run --service") {
		t.Fatalf("sysv:\n%s", s)
	}
	if r := rcdScript(c); !strings.Contains(r, `command="/usr/sbin/daemon"`) || !strings.Contains(r, `command_args="-r -R 3 -P ${pidfile}`) || !strings.Contains(r, "'/opt/Golang TAK/golangtak' run --service") {
		t.Fatalf("rc.d:\n%s", r)
	}
	if l := cronLine(c); !strings.HasPrefix(l, "@reboot '/opt/Golang TAK/golangtak' supervise run") || !strings.HasSuffix(l, "# golangtak") {
		t.Fatalf("cron: %s", l)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{"plain": "plain", "": "''", "a b": "'a b'", "it's": `'it'\''s'`, "$HOME": "'$HOME'"} {
		if got := shellQuote(in); got != want {
			t.Fatalf("%q: got %s want %s", in, got, want)
		}
	}
}

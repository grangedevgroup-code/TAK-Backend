//go:build darwin

package firewall

import (
	"os"
	"strings"
)

const socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

func Open(rules []Rule) (string, error) {
	if Program == "" {
		return "", nil
	}
	if _, err := os.Stat(socketfilterfw); err != nil {
		return "", nil
	}
	out, _ := run(socketfilterfw, "--getglobalstate")
	if !strings.Contains(strings.ToLower(out), "enabled") {
		return "", nil
	}
	run(socketfilterfw, "--add", Program)
	run(socketfilterfw, "--unblockapp", Program)
	return "macOS application firewall", nil
}

func Close(rules []Rule) {
	if Program == "" {
		return
	}
	if _, err := os.Stat(socketfilterfw); err == nil {
		run(socketfilterfw, "--remove", Program)
	}
}

func CloseLegacy(rules []Rule) { Close(rules) }

func Reapply(rules []Rule) {}

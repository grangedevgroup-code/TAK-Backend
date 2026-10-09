//go:build windows

package firewall

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	ruleName       = "GolangTAKServer"
	legacyRuleName = "GolangTAK"
)

func netsh(args ...string) (string, error) {
	return run(filepath.Join(os.Getenv("SystemRoot"), "System32", "netsh.exe"), args...)
}

func Open(rules []Rule) (string, error) {
	rules = Normalize(rules)
	netsh("advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	for _, proto := range []string{"tcp", "udp"} {
		list := ports(rules, proto)
		if len(list) == 0 {
			continue
		}
		out, err := netsh("advfirewall", "firewall", "add", "rule", "name="+ruleName, "dir=in", "action=allow",
			"protocol="+strings.ToUpper(proto), "localport="+strings.Join(list, ","), "profile=any", "enable=yes")
		if err != nil {
			return "Windows Firewall", fmt.Errorf("netsh: %v %s", err, out)
		}
	}
	return "Windows Firewall", nil
}

func Close(rules []Rule) {
	netsh("advfirewall", "firewall", "delete", "rule", "name="+ruleName)
}

func CloseLegacy(rules []Rule) {
	netsh("advfirewall", "firewall", "delete", "rule", "name="+legacyRuleName)
}

func Reapply(rules []Rule) {}

func ports(rules []Rule, proto string) []string {
	var out []string
	for _, r := range rules {
		if r.Proto == proto {
			out = append(out, r.Ports("-"))
		}
	}
	return out
}

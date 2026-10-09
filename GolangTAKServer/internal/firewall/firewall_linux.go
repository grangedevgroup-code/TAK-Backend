//go:build linux

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const (
	comment       = "GolangTAKServer"
	legacyComment = "GolangTAK"
)

func ufwActive() bool {
	if !have("ufw") {
		return false
	}
	out, err := run("ufw", "status")
	return err == nil && strings.Contains(strings.ToLower(out), "status: active")
}

func firewalldActive() bool {
	if !have("firewall-cmd") {
		return false
	}
	out, err := run("firewall-cmd", "--state")
	return err == nil && strings.TrimSpace(out) == "running"
}

func iptablesRestrictive(bin string) bool {
	if !have(bin) {
		return false
	}
	out, err := run(bin, "-S", "INPUT")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "-P" && f[1] == "INPUT" && (f[2] == "DROP" || f[2] == "REJECT") {
			return true
		}
		if len(f) >= 2 && f[0] == "-A" && (strings.HasSuffix(line, "-j REJECT") || strings.HasSuffix(line, "-j DROP") || strings.Contains(line, "-j REJECT --reject-with")) {
			if !strings.Contains(line, "--dport") && !strings.Contains(line, "-s ") && !strings.Contains(line, "--state INVALID") && !strings.Contains(line, "--ctstate INVALID") {
				return true
			}
		}
	}
	return false
}

func ruleSpec(r Rule, tagged bool) []string {
	if tagged {
		return taggedSpec(r, comment)
	}
	return []string{"-p", r.Proto, "-m", r.Proto, "--dport", strconv.Itoa(r.Port), "-j", "ACCEPT"}
}

func taggedSpec(r Rule, tag string) []string {
	spec := []string{"-p", r.Proto, "-m", r.Proto, "--dport", strconv.Itoa(r.Port), "-m", "comment", "--comment", tag}
	return append(spec, "-j", "ACCEPT")
}

func iptablesHas(bin string, r Rule) bool {
	for _, tagged := range []bool{true, false} {
		if _, err := run(bin, append([]string{"-C", "INPUT"}, ruleSpec(r, tagged)...)...); err == nil {
			return true
		}
	}
	return false
}

func iptablesInsert(bin string, r Rule) error {
	out, err := run(bin, append([]string{"-I", "INPUT", "1"}, ruleSpec(r, true)...)...)
	if err == nil {
		return nil
	}
	if _, err2 := run(bin, append([]string{"-I", "INPUT", "1"}, ruleSpec(r, false)...)...); err2 == nil {
		return nil
	}
	return fmt.Errorf("%s could not open %s: %s", bin, r, out)
}

func persistIptables() string {
	if have("netfilter-persistent") {
		if _, err := run("netfilter-persistent", "save"); err == nil {
			return "saved with netfilter-persistent"
		}
	}
	saved := ""
	for _, p := range []struct{ bin, file string }{{"iptables-save", "/etc/iptables/rules.v4"}, {"ip6tables-save", "/etc/iptables/rules.v6"}, {"iptables-save", "/etc/sysconfig/iptables"}, {"ip6tables-save", "/etc/sysconfig/ip6tables"}} {
		if _, err := os.Stat(p.file); err != nil || !have(p.bin) {
			continue
		}
		if out, err := run(p.bin); err == nil && out != "" {
			if os.WriteFile(p.file, []byte(out+"\n"), 0o600) == nil {
				saved = "saved to " + p.file
			}
		}
	}
	if saved == "" {
		return "active until reboot; GolangTAKServer re-applies them when it starts"
	}
	return saved
}

func Open(rules []Rule) (string, error) {
	rules = Normalize(rules)
	if len(rules) == 0 {
		return "no ports to open", nil
	}
	switch {
	case ufwActive():
		var failed []string
		for _, r := range rules {
			if out, err := run("ufw", "allow", r.String(), "comment", comment); err != nil {
				failed = append(failed, r.String()+": "+out)
			}
		}
		if len(failed) > 0 {
			return "ufw", fmt.Errorf("ufw could not open %s", strings.Join(failed, "; "))
		}
		return "ufw", nil
	case firewalldActive():
		var failed []string
		for _, r := range rules {
			if out, err := run("firewall-cmd", "--permanent", "--add-port="+r.String()); err != nil {
				failed = append(failed, r.String()+": "+out)
			}
		}
		run("firewall-cmd", "--reload")
		if len(failed) > 0 {
			return "firewalld", fmt.Errorf("firewalld could not open %s", strings.Join(failed, "; "))
		}
		return "firewalld", nil
	}
	used := []string{}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !iptablesRestrictive(bin) {
			continue
		}
		for _, r := range rules {
			if iptablesHas(bin, r) {
				continue
			}
			if err := iptablesInsert(bin, r); err != nil {
				return bin, err
			}
		}
		used = append(used, bin)
	}
	if len(used) > 0 {
		return strings.Join(used, "+") + " (" + persistIptables() + ")", nil
	}
	return "", nil
}

func Close(rules []Rule) {
	rules = Normalize(rules)
	if have("ufw") {
		for _, r := range rules {
			run("ufw", "delete", "allow", r.String())
		}
	}
	if firewalldActive() {
		for _, r := range rules {
			run("firewall-cmd", "--permanent", "--remove-port="+r.String())
		}
		run("firewall-cmd", "--reload")
	}
	deleteTagged(rules, comment)
}

func CloseLegacy(rules []Rule) {
	deleteTagged(Normalize(rules), legacyComment)
}

func deleteTagged(rules []Rule, tag string) {
	changed := false
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !have(bin) {
			continue
		}
		for _, r := range rules {
			for i := 0; i < 8; i++ {
				if _, err := run(bin, append([]string{"-D", "INPUT"}, taggedSpec(r, tag)...)...); err != nil {
					break
				}
				changed = true
			}
		}
	}
	if changed {
		persistIptables()
	}
}

func Reapply(rules []Rule) {
	rules = Normalize(rules)
	if ufwActive() || firewalldActive() {
		return
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !iptablesRestrictive(bin) {
			continue
		}
		for _, r := range rules {
			if !iptablesHas(bin, r) {
				iptablesInsert(bin, r)
			}
		}
	}
}

func have(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

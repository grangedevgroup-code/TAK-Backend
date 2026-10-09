package firewall

import (
	"sort"
	"strconv"
	"strings"
)

var Program string

type Rule struct {
	Port  int
	Proto string
}

func (r Rule) String() string { return strconv.Itoa(r.Port) + "/" + r.Proto }

func Normalize(rules []Rule) []Rule {
	seen := map[Rule]bool{}
	var out []Rule
	for _, r := range rules {
		r.Proto = strings.ToLower(r.Proto)
		if r.Port <= 0 || r.Port > 65535 || (r.Proto != "tcp" && r.Proto != "udp") || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Proto != out[j].Proto {
			return out[i].Proto < out[j].Proto
		}
		return out[i].Port < out[j].Port
	})
	return out
}

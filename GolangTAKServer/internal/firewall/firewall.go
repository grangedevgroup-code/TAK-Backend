package firewall

import (
	"sort"
	"strconv"
	"strings"
)

var Program string

type Rule struct {
	Port  int
	End   int
	Proto string
}

func (r Rule) Ports(sep string) string {
	if r.End > r.Port {
		return strconv.Itoa(r.Port) + sep + strconv.Itoa(r.End)
	}
	return strconv.Itoa(r.Port)
}

func (r Rule) String() string { return r.Ports("-") + "/" + r.Proto }

func Normalize(rules []Rule) []Rule {
	seen := map[Rule]bool{}
	var out []Rule
	for _, r := range rules {
		r.Proto = strings.ToLower(r.Proto)
		if r.End <= r.Port {
			r.End = 0
		}
		if r.Port <= 0 || r.Port > 65535 || r.End > 65535 || (r.Proto != "tcp" && r.Proto != "udp") || seen[r] {
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

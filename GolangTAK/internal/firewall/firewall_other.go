//go:build !linux && !windows && !darwin

package firewall

func Open(rules []Rule) (string, error) { return "", nil }

func Close(rules []Rule) {}

func Reapply(rules []Rule) {}

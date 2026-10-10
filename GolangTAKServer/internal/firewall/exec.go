//go:build linux || windows || darwin

package firewall

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G702 -- fixed system tools, arguments built by the server
	return strings.TrimSpace(string(out)), err
}

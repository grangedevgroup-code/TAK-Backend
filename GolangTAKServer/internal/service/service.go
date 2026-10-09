package service

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

const (
	StatusRunning      = "running"
	StatusStopped      = "stopped"
	StatusNotInstalled = "not installed"
	StatusUnknown      = "unknown"
)

var ErrNotInstalled = errors.New("service is not installed")

type Config struct {
	Name        string
	DisplayName string
	Description string
	Executable  string
	Args        []string
	DataDir     string
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func WaitFor(c Config, want string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if st, _ := Status(c); st == want {
			return true
		}
		time.Sleep(300 * time.Millisecond)
	}
	return false
}

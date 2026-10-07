//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func enableConsole() {}

func ansiOK() bool {
	fi, err := os.Stdout.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return os.Getenv("TERM") != "dumb"
}

func isAdmin() bool { return os.Geteuid() == 0 }

func elevate(argv []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if v := os.Getenv("GOLANGTAK_DATA"); v != "" {
		has := false
		for _, a := range argv {
			if a == "--data" || strings.HasPrefix(a, "--data=") {
				has = true
			}
		}
		if !has {
			argv = append(argv, "--data", v)
		}
	}
	for _, tool := range []string{"sudo", "doas"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "Administrator (root) rights are required; running with %s.\n", tool)
		return syscall.Exec(p, append([]string{tool, exe}, argv...), os.Environ())
	}
	return errors.New("this command needs root rights; run it as root, for example: su -c 'golangtak " + strings.Join(argv, " ") + "'")
}

func addToPath(dir string) error { return nil }

func removeFromPath(dir string) {}

func scheduleDelete(path string) { os.Remove(path) }

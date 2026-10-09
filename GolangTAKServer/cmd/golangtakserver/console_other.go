//go:build !unix && !windows

package main

import "errors"

func enableConsole() {}

func ansiOK() bool { return false }

func isAdmin() bool { return true }

func elevate(argv []string) error {
	return errors.New("administrator rights are required")
}

func addToPath(dir string) error { return nil }

func removeFromPath(dir string) {}

func scheduleDelete(path string) {}

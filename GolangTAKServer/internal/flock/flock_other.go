//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package flock

import "os"

func lockFile(f *os.File) error { return nil }

func unlockFile(f *os.File) {}

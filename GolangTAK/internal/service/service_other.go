//go:build !unix && !windows

package service

import "errors"

var errUnsupported = errors.New("services are not supported on this platform; run in the foreground")

func Manager() string { return "none" }

func IsAdmin() bool { return true }

func Interactive() bool { return true }

func RunAsService(name string, fn func(stop <-chan struct{}) error) (bool, error) { return false, nil }

func Install(c Config) error { return errUnsupported }

func Uninstall(c Config) error { return nil }

func Start(c Config) error { return errUnsupported }

func Stop(c Config) error { return nil }

func Restart(c Config) error { return errUnsupported }

func Status(c Config) (string, error) { return StatusNotInstalled, nil }

func PIDFile(c Config) string { return "" }

func LogHint(c Config) string { return "" }

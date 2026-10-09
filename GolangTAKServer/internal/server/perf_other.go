//go:build !linux && !windows && !darwin && !freebsd

package server

func readOSStats(dir string) osStats {
	return osStats{}
}

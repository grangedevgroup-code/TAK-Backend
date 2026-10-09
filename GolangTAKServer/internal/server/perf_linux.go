//go:build linux

package server

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func readOSStats(dir string) osStats {
	var st osStats
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		var free, buffers, cached uint64
		haveAvail := false
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			v, _ := strconv.ParseUint(fields[1], 10, 64)
			v *= 1024
			switch fields[0] {
			case "MemTotal:":
				st.MemTotal = v
			case "MemAvailable:":
				st.MemAvail, haveAvail = v, true
			case "MemFree:":
				free = v
			case "Buffers:":
				buffers = v
			case "Cached:":
				cached = v
			}
		}
		f.Close()
		if !haveAvail {
			st.MemAvail = free + buffers + cached
		}
		st.HaveAvail = st.MemTotal > 0
	}
	if b, err := os.ReadFile("/proc/stat"); err == nil {
		line, _, _ := strings.Cut(string(b), "\n")
		fields := strings.Fields(line)
		if len(fields) > 4 && fields[0] == "cpu" {
			var total, idle uint64
			for i, f := range fields[1:] {
				v, _ := strconv.ParseUint(f, 10, 64)
				if i == 8 || i == 9 {
					continue
				}
				total += v
				if i == 3 || i == 4 {
					idle += v
				}
			}
			st.CPUTotal, st.CPUBusy, st.HaveCPU = total, total-idle, total > 0
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) >= 3 {
			for _, f := range fields[:3] {
				v, _ := strconv.ParseFloat(f, 64)
				st.Load = append(st.Load, v)
			}
		}
	}
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		st.ProcCPU = time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
		st.HaveProc = true
	}
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		fields := strings.Fields(string(b))
		if len(fields) >= 2 {
			pages, _ := strconv.ParseUint(fields[1], 10, 64)
			st.ProcRSS = pages * uint64(os.Getpagesize())
		}
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(dir, &fs) == nil {
		st.DiskTotal = uint64(fs.Blocks) * uint64(fs.Bsize)
		st.DiskFree = uint64(fs.Bavail) * uint64(fs.Bsize)
		st.HaveDisk = st.DiskTotal > 0
	}
	return st
}

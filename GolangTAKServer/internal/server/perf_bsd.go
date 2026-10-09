//go:build darwin || freebsd

package server

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"time"
)

func sysctlUint64(name string) uint64 {
	s, err := syscall.Sysctl(name)
	if err != nil {
		return 0
	}
	b := []byte(s)
	for len(b) < 8 {
		b = append(b, 0)
	}
	return binary.LittleEndian.Uint64(b[:8])
}

func readOSStats(dir string) osStats {
	var st osStats
	if runtime.GOOS == "darwin" {
		st.MemTotal = sysctlUint64("hw.memsize")
	} else {
		st.MemTotal = sysctlUint64("hw.physmem")
		pageSize := sysctlUint64("hw.pagesize") & 0xffffffff
		free := sysctlUint64("vm.stats.vm.v_free_count") & 0xffffffff
		inactive := sysctlUint64("vm.stats.vm.v_inactive_count") & 0xffffffff
		if pageSize > 0 {
			st.MemAvail = (free + inactive) * pageSize
			st.HaveAvail = st.MemTotal > 0
		}
	}
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		st.ProcCPU = time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
		st.HaveProc = true
	}
	var fs syscall.Statfs_t
	if syscall.Statfs(dir, &fs) == nil {
		st.DiskTotal = uint64(fs.Blocks) * uint64(fs.Bsize)
		st.DiskFree = uint64(fs.Bavail) * uint64(fs.Bsize)
		st.HaveDisk = st.DiskTotal > 0
	}
	return st
}

//go:build windows

package server

import (
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemory     = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemTimes   = kernel32.NewProc("GetSystemTimes")
	procGetDiskFreeSpace = kernel32.NewProc("GetDiskFreeSpaceExW")
	procProcessMemory    = kernel32.NewProc("K32GetProcessMemoryInfo")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func filetime64(f syscall.Filetime) uint64 {
	return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)
}

func readOSStats(dir string) osStats {
	var st osStats
	m := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	if r, _, _ := procGlobalMemory.Call(uintptr(unsafe.Pointer(&m))); r != 0 {
		st.MemTotal, st.MemAvail, st.HaveAvail = m.TotalPhys, m.AvailPhys, true
	}
	var idle, kernel, user syscall.Filetime
	if r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user))); r != 0 {
		total := filetime64(kernel) + filetime64(user)
		st.CPUTotal, st.CPUBusy, st.HaveCPU = total, total-filetime64(idle), total > 0
	}
	h, err := syscall.GetCurrentProcess()
	if err == nil {
		var created, exited, k, u syscall.Filetime
		if syscall.GetProcessTimes(h, &created, &exited, &k, &u) == nil {
			st.ProcCPU = time.Duration((filetime64(k) + filetime64(u)) * 100)
			st.HaveProc = true
		}
		pm := processMemoryCounters{Cb: uint32(unsafe.Sizeof(processMemoryCounters{}))}
		if r, _, _ := procProcessMemory.Call(uintptr(h), uintptr(unsafe.Pointer(&pm)), uintptr(pm.Cb)); r != 0 {
			st.ProcRSS = uint64(pm.WorkingSetSize)
		}
	}
	if p, err := syscall.UTF16PtrFromString(dir); err == nil {
		var avail, total, free uint64
		if r, _, _ := procGetDiskFreeSpace.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&avail)), uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&free))); r != 0 {
			st.DiskTotal, st.DiskFree, st.HaveDisk = total, avail, total > 0
		}
	}
	return st
}

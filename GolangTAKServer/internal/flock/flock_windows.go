//go:build windows

package flock

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	errLockViolation        = syscall.Errno(33)
	errIOPending            = syscall.Errno(997)
)

func lockFile(f *os.File) error {
	ol := syscall.Overlapped{OffsetHigh: 1}
	r, _, err := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r != 0 {
		return nil
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == errLockViolation || errno == errIOPending) {
		return ErrLocked
	}
	return err
}

func unlockFile(f *os.File) {
	ol := syscall.Overlapped{OffsetHigh: 1}
	procUnlockFileEx.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
}

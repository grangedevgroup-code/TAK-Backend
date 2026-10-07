//go:build windows

package service

import (
	"strings"
	"syscall"
	"unsafe"
)

var (
	procRegSetValueExW      = advapi32.NewProc("RegSetValueExW")
	user32                  = syscall.NewLazyDLL("user32.dll")
	procSendMessageTimeoutW = user32.NewProc("SendMessageTimeoutW")
)

const (
	envKey          = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	regExpandSZ     = 2
	hwndBroadcast   = 0xffff
	wmSettingChange = 0x001A
	smtoAbortIfHung = 0x0002
)

func readSystemPath() (string, syscall.Handle, error) {
	var h syscall.Handle
	key, _ := syscall.UTF16PtrFromString(envKey)
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, key, 0, syscall.KEY_QUERY_VALUE|syscall.KEY_SET_VALUE, &h); err != nil {
		return "", 0, err
	}
	name, _ := syscall.UTF16PtrFromString("Path")
	var typ, n uint32
	if err := syscall.RegQueryValueEx(h, name, nil, &typ, nil, &n); err != nil {
		syscall.RegCloseKey(h)
		return "", 0, err
	}
	buf := make([]uint16, n/2+1)
	if err := syscall.RegQueryValueEx(h, name, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil {
		syscall.RegCloseKey(h)
		return "", 0, err
	}
	return syscall.UTF16ToString(buf), h, nil
}

func writeSystemPath(h syscall.Handle, value string) error {
	name, _ := syscall.UTF16PtrFromString("Path")
	data, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	r, _, _ := procRegSetValueExW.Call(uintptr(h), uintptr(unsafe.Pointer(name)), 0, regExpandSZ, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
	if r != 0 {
		return syscall.Errno(r)
	}
	env, _ := syscall.UTF16PtrFromString("Environment")
	var result uintptr
	procSendMessageTimeoutW.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000, uintptr(unsafe.Pointer(&result)))
	return nil
}

func samePath(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, `\`), strings.TrimRight(b, `\`))
}

func AddToSystemPath(dir string) error {
	cur, h, err := readSystemPath()
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(h)
	for _, p := range strings.Split(cur, ";") {
		if samePath(p, dir) {
			return nil
		}
	}
	next := strings.TrimRight(cur, ";")
	if next != "" {
		next += ";"
	}
	return writeSystemPath(h, next+dir)
}

func RemoveFromSystemPath(dir string) error {
	cur, h, err := readSystemPath()
	if err != nil {
		return err
	}
	defer syscall.RegCloseKey(h)
	var keep []string
	removed := false
	for _, p := range strings.Split(cur, ";") {
		if samePath(p, dir) {
			removed = true
			continue
		}
		keep = append(keep, p)
	}
	if !removed {
		return nil
	}
	return writeSystemPath(h, strings.Join(keep, ";"))
}

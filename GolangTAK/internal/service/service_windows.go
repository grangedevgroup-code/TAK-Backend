//go:build windows

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	advapi32                          = syscall.NewLazyDLL("advapi32.dll")
	shell32                           = syscall.NewLazyDLL("shell32.dll")
	procStartServiceCtrlDispatcherW   = advapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = advapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = advapi32.NewProc("SetServiceStatus")
	procIsUserAnAdmin                 = shell32.NewProc("IsUserAnAdmin")
	procShellExecuteW                 = shell32.NewProc("ShellExecuteW")
)

const (
	serviceWin32OwnProcess = 0x10
	stateStopped           = 1
	stateStartPending      = 2
	stateStopPending       = 3
	stateRunning           = 4
	acceptStop             = 0x1
	acceptShutdown         = 0x4
	controlStop            = 1
	controlInterrogate     = 4
	controlShutdown        = 5
	errNotService          = 1063
)

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type tableEntry struct {
	name *uint16
	proc uintptr
}

var (
	svcName   string
	svcFn     func(stop <-chan struct{}) error
	svcHandle uintptr
	svcStop   chan struct{}
	stopOnce  sync.Once
	svcErr    error
	checkPt   uint32
)

func setStatus(state, accepts, exitCode uint32) {
	checkPt++
	st := serviceStatus{ServiceType: serviceWin32OwnProcess, CurrentState: state, ControlsAccepted: accepts, CheckPoint: checkPt, WaitHint: 30000}
	if state == stateRunning || state == stateStopped {
		st.CheckPoint, st.WaitHint = 0, 0
	}
	if exitCode != 0 {
		st.Win32ExitCode = 1066
		st.ServiceSpecificExitCode = exitCode
	}
	procSetServiceStatus.Call(svcHandle, uintptr(unsafe.Pointer(&st)))
}

func handler(ctrl, eventType, eventData, ctx uintptr) uintptr {
	switch uint32(ctrl) {
	case controlStop, controlShutdown:
		setStatus(stateStopPending, 0, 0)
		stopOnce.Do(func() { close(svcStop) })
		return 0
	case controlInterrogate:
		return 0
	}
	return 120
}

func serviceMain(argc, argv uintptr) uintptr {
	name, _ := syscall.UTF16PtrFromString(svcName)
	h, _, _ := procRegisterServiceCtrlHandlerExW.Call(uintptr(unsafe.Pointer(name)), syscall.NewCallback(handler), 0)
	svcHandle = h
	setStatus(stateStartPending, 0, 0)
	svcStop = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- svcFn(svcStop) }()
	setStatus(stateRunning, acceptStop|acceptShutdown, 0)
	svcErr = <-done
	code := uint32(0)
	if svcErr != nil {
		code = 1
	}
	setStatus(stateStopped, 0, code)
	return 0
}

func RunAsService(name string, fn func(stop <-chan struct{}) error) (bool, error) {
	svcName, svcFn = name, fn
	n, _ := syscall.UTF16PtrFromString(name)
	table := []tableEntry{{name: n, proc: syscall.NewCallback(serviceMain)}, {}}
	r, _, err := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if r == 0 {
		var errno syscall.Errno
		if errors.As(err, &errno) && errno == errNotService {
			return false, nil
		}
		return false, err
	}
	return true, svcErr
}

func Interactive() bool { return true }

func Manager() string { return "windows" }

func IsAdmin() bool {
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

func RelaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(quoted, " "))
	cwd, _ := os.Getwd()
	dir, _ := syscall.UTF16PtrFromString(cwd)
	r, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), uintptr(unsafe.Pointer(dir)), 1)
	if r <= 32 {
		return fmt.Errorf("could not request administrator rights (code %d)", r)
	}
	return nil
}

func sc(args ...string) (string, error) {
	return run(60*time.Second, filepath.Join(os.Getenv("SystemRoot"), "System32", "sc.exe"), args...)
}

func binPath(c Config) string {
	parts := []string{syscall.EscapeArg(c.Executable)}
	for _, a := range c.Args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

func Install(c Config) error {
	if st, _ := Status(c); st != StatusNotInstalled {
		Stop(c)
		if out, err := sc("config", c.Name, "binPath=", binPath(c), "start=", "auto", "DisplayName=", c.DisplayName); err != nil {
			return fmt.Errorf("sc config: %v %s", err, out)
		}
	} else if out, err := sc("create", c.Name, "binPath=", binPath(c), "start=", "auto", "DisplayName=", c.DisplayName); err != nil {
		return fmt.Errorf("sc create: %v %s", err, out)
	}
	sc("description", c.Name, c.Description)
	if out, err := sc("failure", c.Name, "reset=", "86400", "actions=", "restart/3000/restart/5000/restart/10000"); err != nil {
		return fmt.Errorf("sc failure: %v %s", err, out)
	}
	sc("failureflag", c.Name, "1")
	sc("config", c.Name, "start=", "delayed-auto")
	sc("config", c.Name, "start=", "auto")
	return nil
}

func Uninstall(c Config) error {
	Stop(c)
	if out, err := sc("delete", c.Name); err != nil && !strings.Contains(out, "1060") {
		return fmt.Errorf("sc delete: %v %s", err, out)
	}
	return nil
}

func Start(c Config) error {
	out, err := sc("start", c.Name)
	if err != nil && !strings.Contains(out, "1056") {
		return fmt.Errorf("sc start: %v %s", err, out)
	}
	return nil
}

func Stop(c Config) error {
	out, err := sc("stop", c.Name)
	if err != nil && !strings.Contains(out, "1062") && !strings.Contains(out, "1060") {
		return fmt.Errorf("sc stop: %v %s", err, out)
	}
	WaitFor(c, StatusStopped, 30*time.Second)
	return nil
}

func Restart(c Config) error {
	Stop(c)
	return Start(c)
}

func Status(c Config) (string, error) {
	out, err := sc("query", c.Name)
	if strings.Contains(out, "1060") {
		return StatusNotInstalled, nil
	}
	if err != nil {
		return StatusUnknown, err
	}
	switch {
	case strings.Contains(out, "RUNNING"):
		return StatusRunning, nil
	case strings.Contains(out, "STOPPED"):
		return StatusStopped, nil
	case strings.Contains(out, "START_PENDING"):
		return StatusRunning, nil
	}
	return StatusUnknown, nil
}

func PIDFile(c Config) string { return "" }

func LogHint(c Config) string {
	return "golangtak logs -f"
}
